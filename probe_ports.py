#!/usr/bin/env python3
"""Diagnostic Port Prober for Raspberry Pi Smart Backplane.

Tests /dev/ttyACM0 and /dev/ttyUSB0 at standard baud rates (115200, 9600)
to detect live incoming bytes from Arduino UNO, ESP8266, or ESP32.
"""

import os
import sys
import time

PORTS = ["/dev/ttyACM0", "/dev/ttyUSB0"]
BAUDS = [115200, 9600, 57600]


def probe_port(port_path: str, baud: int, timeout_sec: float = 3.0):
    if not os.path.exists(port_path):
        print(f"[-] {port_path}: Port does not exist on this system.")
        return False

    print(f"\n[*] Probing {port_path} at {baud} baud (listening for {timeout_sec}s)...")
    try:
        # Check if pyserial is available
        try:
            import serial
            ser = serial.Serial(port=port_path, baudrate=baud, timeout=0.5)
            # Release reset lines on ESP boards
            ser.dtr = False
            ser.rts = False
            time.sleep(0.2)
            ser.dtr = True
            ser.rts = False
            
            start = time.time()
            total_bytes = b""
            while time.time() - start < timeout_sec:
                data = ser.read(128)
                if data:
                    total_bytes += data
                    print(f"    [+] Received {len(data)} bytes: {repr(data)}")
                    break
            ser.close()
            if total_bytes:
                print(f"[SUCCESS] {port_path} is ACTIVE at {baud} baud! Sample: {total_bytes[:80]}")
                return True
        except ImportError:
            # Fallback using stty and non-blocking read
            import termios
            import fcntl
            
            fd = os.open(port_path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            attrs = termios.tcgetattr(fd)
            # Raw mode
            attrs[0] &= ~(termios.IGNBRK | termios.BRKINT | termios.PARMRK | termios.ISTRIP | termios.INLCR | termios.IGNCR | termios.ICRNL | termios.IXON)
            attrs[1] &= ~termios.OPOST
            attrs[2] &= ~(termios.CSIZE | termios.PARENB)
            attrs[2] |= (termios.CS8 | termios.CREAD | termios.CLOCAL)
            attrs[3] &= ~(termios.ECHO | termios.ECHONL | termios.ICANON | termios.ISIG | termios.IEXTEN)
            
            b_map = {9600: termios.B9600, 115200: termios.B115200, 57600: termios.B57600}
            b_const = b_map.get(baud, termios.B115200)
            attrs[4] = b_const
            attrs[5] = b_const
            attrs[6][termios.VMIN] = 0
            attrs[6][termios.VTIME] = 5
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
            
            start = time.time()
            total_bytes = b""
            while time.time() - start < timeout_sec:
                try:
                    chunk = os.read(fd, 128)
                    if chunk:
                        total_bytes += chunk
                        print(f"    [+] Received {len(chunk)} bytes: {repr(chunk)}")
                        break
                except BlockingIOError:
                    pass
                time.sleep(0.1)
            os.close(fd)
            if total_bytes:
                print(f"[SUCCESS] {port_path} is ACTIVE at {baud} baud! Sample: {total_bytes[:80]}")
                return True

        print(f"    [-] No data received on {port_path} at {baud} baud.")
        return False
    except Exception as e:
        print(f"    [!] Error accessing {port_path}: {e}")
        return False


def main():
    print("=" * 65)
    print("   SMART BACKPLANE SERIAL PORT PROBER")
    print("=" * 65)
    
    found_any = False
    for port in PORTS:
        if os.path.exists(port):
            for baud in BAUDS:
                if probe_port(port, baud, timeout_sec=2.5):
                    found_any = True
                    break
        else:
            print(f"[-] {port}: Not found.")

    print("\n" + "=" * 65)
    if found_any:
        print("[+] Active serial device detected! See port and baud above.")
    else:
        print("[-] No serial data detected on any port.")
        print("    Troubleshooting steps:")
        print("    1. Is the microcontroller sketch running and calling Serial.println() in loop()?")
        print("    2. On ESP8266/NodeMCU, press the 'RST' button while this script is running.")
        print("    3. Check USB cable - ensure it is a data cable, not power-only.")
    print("=" * 65)


if __name__ == "__main__":
    main()
