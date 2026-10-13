#!/usr/bin/env python3
"""Smart Backplane Trust Engine --- Live Hardware Ingestion Runner.

Connects to a physical ESP32 streaming INA3221 voltage and current sensor telemetry
over UART / Serial on Raspberry Pi 3B+ (e.g. /dev/serial0, /dev/ttyUSB0, /dev/ttyS0).

Features:
- Native POSIX serial reader with automatic termios baud rate configuration
  (zero third-party dependencies required; seamlessly uses pyserial if present).
- Streams bytes directly into ESP32FrameParser with real-time CRC-32 integrity checking.
- Auto-registers docked devices and evaluates Trust Engine admission/monitoring policies.
- Live colorized terminal dashboard displaying voltage, current, power, and state verdicts.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import sys
import time
from typing import Dict, Optional, Union

from trust_engine.audit import AuditEvent, AuditEventType, AuditLog
from trust_engine.device import Device
from trust_engine.engine import TrustEngine
from trust_engine.esp32_transport import (
    CURRENT_PROTOCOL_VERSION,
    ESP32Frame,
    ESP32FrameParser,
    FrameErrorReason,
    SyntheticESP32Source,
)
from trust_engine.policy import DecisionType, PolicyDecision, PolicyEngine
from trust_engine.registry import DeviceRegistry
from trust_engine.states import DeviceState
from trust_engine.telemetry import PhysicalTelemetry, TelemetryValidator

# --- Terminal Styling ---
IS_TTY = sys.stdout.isatty()
GREEN = "\033[92m" if IS_TTY else ""
RED = "\033[91m" if IS_TTY else ""
YELLOW = "\033[93m" if IS_TTY else ""
CYAN = "\033[96m" if IS_TTY else ""
BOLD = "\033[1m" if IS_TTY else ""
RESET = "\033[0m" if IS_TTY else ""


def open_serial_port(port_path: str, baud_rate: int = 115200):
    """Open serial port using pyserial if available, or native Linux termios.

    Returns a file-like reader object or a serial.Serial object.
    """
    # 1. Try pyserial if installed
    try:
        import serial  # type: ignore

        ser = serial.Serial(port=port_path, baudrate=baud_rate, timeout=1.0)
        return ser
    except ImportError:
        pass

    # 2. Native POSIX fallback on Linux / Raspberry Pi OS
    if platform.system() != "Windows":
        import fcntl
        import termios

        # Open non-blocking first to avoid hanging on carrier detect
        fd = os.open(port_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)

        # Map baud rate
        baud_constants = {
            9600: termios.B9600,
            19200: termios.B19200,
            38400: termios.B38400,
            57600: termios.B57600,
            115200: termios.B115200,
            230400: getattr(termios, "B230400", termios.B115200),
        }
        b_const = baud_constants.get(baud_rate, termios.B115200)

        attrs = termios.tcgetattr(fd)
        # Raw mode configuration: 8N1, disable flow control
        attrs[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)
        attrs[1] &= ~termios.OPOST
        attrs[2] &= ~(termios.CSIZE | termios.PARENB)
        attrs[2] |= (termios.CS8 | termios.CREAD | termios.CLOCAL)
        attrs[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)

        # Set baud rate
        attrs[4] = b_const  # input speed
        attrs[5] = b_const  # output speed

        # VMIN=1, VTIME=10 (1.0 second timeout)
        attrs[6][termios.VMIN] = 0
        attrs[6][termios.VTIME] = 10

        termios.tcsetattr(fd, termios.TCSANOW, attrs)

        # Switch back to blocking mode with timeout
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags & ~os.O_NONBLOCK)

        class PosixSerialWrapper:
            def __init__(self, fd_val: int):
                self._fd = fd_val

            def read(self, size: int = 64) -> bytes:
                try:
                    return os.read(self._fd, size)
                except BlockingIOError:
                    return b""
                except Exception:
                    return b""

            def close(self):
                os.close(self._fd)

        return PosixSerialWrapper(fd)

    raise RuntimeError(
        f"Cannot open serial port '{port_path}' without pyserial on {platform.system()}. "
        "Run: pip install pyserial"
    )


def find_default_serial_port() -> Optional[str]:
    """Auto-detect common Raspberry Pi and USB serial ports."""
    candidates = [
        "/dev/serial0",   # Primary Raspberry Pi UART
        "/dev/ttyUSB0",   # USB-to-UART adapter / ESP32 USB
        "/dev/ttyACM0",   # ESP32 CDC USB device
        "/dev/ttyS0",     # Secondary Pi mini-UART
        "/dev/cu.usbserial-0001",  # macOS USB
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


class LiveTrustMonitor:
    """Manages real-time ingestion from physical ESP32 and TrustEngine lifecycle."""

    def __init__(self, serial_stream, registry: Optional[DeviceRegistry] = None):
        self.stream = serial_stream
        self.registry = registry or DeviceRegistry()
        self.audit_log = AuditLog()
        self.engine = TrustEngine(registry=self.registry)
        self.parser = ESP32FrameParser(
            registry=self.registry,
            audit_log=self.audit_log,
            require_crc=True,
            track_sequence=True,
        )

        # Pre-seed dock ports with registered default identity placeholders
        self._ensure_dock_ports_initialized()

    def _ensure_dock_ports_initialized(self):
        """Register default dock port devices if not already present."""
        for port_num in (1, 2, 3):
            dev_id = f"dock-device-port{port_num}"
            if dev_id not in self.registry:
                dev = Device(
                    device_id=dev_id,
                    mac_address=f"00:11:22:33:44:0{port_num}",
                    physical_port=port_num,
                )
                self.engine.register_device(dev)

    def run_loop(self):
        """Continuous live telemetry ingestion loop."""
        print(f"\n{GREEN}[READY]{RESET} Listening for live ESP32 telemetry frames...")
        print(f"{CYAN}[INFO]{RESET} Press Ctrl+C at any time to halt monitor.\n")
        print(f"{BOLD}{'PORT':<6} | {'DEVICE ID':<22} | {'VOLTAGE':<9} | {'CURRENT':<9} | {'TEMP':<7} | {'CRC-32':<10} | {'TRUST STATE':<12}{RESET}")
        print("-" * 85)

        total_frames = 0
        valid_frames = 0
        corrupt_frames = 0

        try:
            while True:
                # Read chunks from serial transport
                chunk = self.stream.read(64)
                if not chunk:
                    time.sleep(0.01)
                    continue

                parse_results = self.parser.feed(chunk)
                for res in parse_results:
                    total_frames += 1

                    if not res.is_success:
                        corrupt_frames += 1
                        err = res.error
                        reason_name = err.reason.value if err else "UNKNOWN_ERROR"
                        err_msg = err.message if err else "Corrupted frame"
                        print(f"{RED}[FRAME REJECTED]{RESET} Reason: {YELLOW}{reason_name}{RESET} | {err_msg}")
                        continue

                    valid_frames += 1
                    telem = res.telemetry
                    frame = res.frame
                    dev_id = telem.device_id
                    port = telem.physical_port

                    # Evaluate admission if in quarantine
                    current_status = self.registry.lookup(dev_id).status
                    if current_status == DeviceState.QUARANTINED:
                        # Attempt admission evaluation with current physical evidence
                        decision = self.engine.evaluate_admission(
                            device_id=dev_id,
                            physical_telemetry=[telem],
                            network_telemetry=None,
                        )
                    elif current_status in (DeviceState.TRUSTED, DeviceState.ANOMALOUS):
                        decision = self.engine.evaluate_monitoring(
                            device_id=dev_id,
                            physical_telemetry=[telem],
                            network_telemetry=None,
                        )
                    else:
                        decision = None

                    updated_status = self.registry.lookup(dev_id).status

                    # Colorize state
                    state_color = GREEN if updated_status == DeviceState.TRUSTED else (YELLOW if updated_status == DeviceState.QUARANTINED else RED)
                    temp_str = f"{telem.temperature_c:.1f}°C" if telem.temperature_c is not None else "N/A"

                    print(
                        f"Port {port:<2} | "
                        f"{dev_id:<22} | "
                        f"{telem.voltage_v:>6.2f} V  | "
                        f"{telem.current_a:>6.3f} A  | "
                        f"{temp_str:<7} | "
                        f"CRC: {GREEN}{frame.crc32}{RESET} | "
                        f"{state_color}{updated_status.name}{RESET}"
                    )

        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}[SHUTDOWN]{RESET} Monitor halted by user.")
        finally:
            self._print_summary(total_frames, valid_frames, corrupt_frames)

    def _print_summary(self, total: int, valid: int, corrupt: int):
        """Print session statistics and audit trail summary."""
        print(f"\n{BOLD}======================================================================{RESET}")
        print(f"{BOLD}                LIVE SESSION TELEMETRY SUMMARY                        {RESET}")
        print(f"{BOLD}======================================================================{RESET}")
        print(f"Total Raw Frames Processed:   {total}")
        print(f"Valid Checksum Frames:        {GREEN}{valid}{RESET}")
        print(f"Rejected / Corrupt Frames:    {RED if corrupt else GREEN}{corrupt}{RESET}")
        print(f"Audit Trail Events Recorded:  {len(self.audit_log)}")
        print(f"Registered Devices in Memory: {len(self.registry)}")
        for d in self.registry.list_devices():
            print(f"  - Device '{d.device_id}' on Port {d.physical_port}: {d.status.name}")
        print(f"{BOLD}======================================================================{RESET}")


def main() -> int:
    """CLI entrypoint."""
    parser = argparse.ArgumentParser(
        description="Smart Backplane Trust Engine --- Live Hardware Telemetry Monitor"
    )
    parser.add_argument(
        "--port",
        "-p",
        default=None,
        help="Serial port path (e.g. /dev/serial0, /dev/ttyUSB0). Auto-detects if omitted.",
    )
    parser.add_argument(
        "--baud",
        "-b",
        type=int,
        default=115200,
        help="Baud rate (default: 115200)",
    )
    parser.add_argument(
        "--simulated-source",
        action="store_true",
        help="Run in loopback mode with SyntheticESP32Source if hardware is not connected yet.",
    )

    args = parser.parse_args()

    print(f"{BOLD}======================================================================{RESET}")
    print(f"{BOLD}   SMART BACKPLANE TRUST ENGINE --- LIVE HARDWARE MONITOR            {RESET}")
    print(f"{BOLD}======================================================================{RESET}")

    if args.simulated_source:
        print(f"{YELLOW}[MODE]{RESET} Running in synthetic simulation stream mode.")
        import io

        class MockStream:
            def __init__(self):
                self.source = SyntheticESP32Source()
                self._buffer = bytearray()
                self._last_time = 0.0

            def read(self, size: int = 64) -> bytes:
                now = time.time()
                if now - self._last_time > 1.0:  # Emit 1 frame per second
                    self._last_time = now
                    port = (int(now) % 3) + 1
                    line = self.source.make_frame(
                        port=port,
                        voltage_v=5.05 + ((int(now) % 5) * 0.02),
                        current_a=0.35 + ((int(now) % 4) * 0.05),
                        temp_c=36.0,
                        device_id=f"dock-device-port{port}",
                    )
                    self._buffer.extend(line.encode("utf-8"))

                chunk = bytes(self._buffer[:size])
                del self._buffer[:size]
                return chunk

        stream = MockStream()
    else:
        port_path = args.port or find_default_serial_port()
        if not port_path:
            print(f"{RED}[ERROR]{RESET} No serial port specified and none auto-detected.")
            print(f"Common ports: /dev/serial0, /dev/ttyUSB0, /dev/ttyACM0")
            print(f"Usage: python3 run_live.py --port /dev/serial0 --baud 115200")
            print(f"Or test the dashboard now with: python3 run_live.py --simulated-source")
            return 1

        print(f"{CYAN}[CONFIG]{RESET} Opening Serial Port: {BOLD}{port_path}{RESET} at {args.baud} baud...")
        try:
            stream = open_serial_port(port_path, baud_rate=args.baud)
            print(f"{GREEN}[CONNECTED]{RESET} Port successfully opened.")
        except Exception as exc:
            print(f"{RED}[ERROR]{RESET} Failed to open serial port '{port_path}': {exc}")
            print(f"{YELLOW}Raspberry Pi Troubleshooting tips:{RESET}")
            print(f"  1. Ensure UART is enabled in raspi-config: sudo raspi-config -> Interface -> Serial")
            print(f"  2. Add user to dialout group: sudo usermod -a -G dialout $USER")
            print(f"  3. Check device permissions: ls -l {port_path}")
            return 1

    monitor = LiveTrustMonitor(stream)
    monitor.run_loop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
