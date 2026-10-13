#!/usr/bin/env python3
"""Smart Backplane Trust Engine --- Multi-Device Bench Real-Time Simulation.

Simulates a physical dual-device dock scenario progressing in real time:
1. Arduino UNO on Port 1:
   - Low idle power (~5.02V, ~0.048A / 48mA).
   - Generates zero network traffic (offline microcontroller).
2. ESP8266 with WiFi Module on Port 2:
   - Low, benign power draw (~5.01V, ~0.092A / 92mA) despite active radio.
   - Makes outbound network connections via Raspberry Pi gateway (192.168.1.1).
   - Interacts with Application Layer protocols: DNS, NTP, MQTT, and HTTPS.
   - Connects to an external destination (198.51.100.77:8443) with an INVALID TLS CERTIFICATE.
   - Demonstrates that physical power monitoring is blind to application-layer security threats.
   - Shows the Raspberry Pi's step-by-step decision to transition the ESP8266 from TRUSTED -> ISOLATED.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import List, Optional

from trust_engine.audit import AuditEvent, AuditEventType, AuditLog
from trust_engine.device import Device
from trust_engine.enforcement import EnforcementActionType, SimulatedEnforcementAdapter
from trust_engine.engine import TrustEngine
from trust_engine.policy import DecisionType, PolicyConfig, PolicyEngine
from trust_engine.registry import DeviceRegistry
from trust_engine.states import DeviceState
from trust_engine.telemetry import NetworkTelemetry, PhysicalTelemetry, TelemetryValidator

# --- Terminal Styling ---
IS_TTY = sys.stdout.isatty()
GREEN = "\033[92m" if IS_TTY else ""
RED = "\033[91m" if IS_TTY else ""
YELLOW = "\033[93m" if IS_TTY else ""
CYAN = "\033[96m" if IS_TTY else ""
BOLD = "\033[1m" if IS_TTY else ""
MAGENTA = "\033[95m" if IS_TTY else ""
DIM = "\033[2m" if IS_TTY else ""
RESET = "\033[0m" if IS_TTY else ""


def print_banner(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{'=' * 78}{RESET}")
    print(f"{BOLD}{CYAN}   {text}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 78}{RESET}\n")
    sys.stdout.flush()


def print_step(step_num: int, title: str, tick: str) -> None:
    print(f"\n{BOLD}{YELLOW}[STEP {step_num}] {title} {DIM}{tick}{RESET}")
    print("-" * 78)
    sys.stdout.flush()


def run_simulation(pace: float = 0.5) -> int:
    """Execute the Arduino UNO + ESP8266 multi-device dock simulation in real-time.
    
    Args:
        pace: Sleep interval in seconds between real-time events. Set to 0.0 for instant execution.
    """
    t_start = time.monotonic()

    def tick() -> str:
        elapsed = time.monotonic() - t_start
        return f"[T+{elapsed:05.2f}s]"

    def pace_pause(multiplier: float = 1.0) -> None:
        if pace > 0:
            time.sleep(pace * multiplier)
            sys.stdout.flush()

    print_banner("SMART BACKPLANE --- REAL-TIME BENCH DOCK SIMULATION")

    print(f"{BOLD}NETWORK TOPOLOGY (Managed by Raspberry Pi Gateway):{RESET}")
    print(f"  • Raspberry Pi Gateway IP:     {BOLD}192.168.1.1{RESET} (Backplane Controller & Inspector)")
    print(f"  • Subnet:                      {BOLD}192.168.1.0/24{RESET}")
    print(f"  • Dock Port 1:                 {BOLD}Arduino UNO{RESET} (Offline Microcontroller, 00:1A:79:AB:CD:01)")
    print(f"  • Dock Port 2:                 {BOLD}ESP8266 WiFi{RESET} (DHCP IP: 192.168.1.105, MAC: 5C:CF:7F:4A:22:90)")
    print(f"  • Local Network Services:      DNS (192.168.1.1:53), NTP (192.168.1.1:123), MQTT (192.168.1.10:1883)")
    print(f"  • Real-Time Cadence:           {CYAN}{'Real-Time Paced (' + str(pace) + 's/step)' if pace > 0 else 'Instant Execution'}{RESET}")
    print("-" * 78)
    sys.stdout.flush()
    pace_pause(1.2)

    # Initialize Trust Engine components
    registry = DeviceRegistry()
    audit_log = AuditLog()
    enforcement = SimulatedEnforcementAdapter(registry=registry, audit_log=audit_log)
    policy_engine = PolicyEngine()
    engine = TrustEngine(registry=registry, policy_engine=policy_engine)

    # --------------------------------------------------------------------------
    # STEP 1: Device Docking & Zero-Trust Quarantine
    # --------------------------------------------------------------------------
    print_step(1, "Physical Docking & Zero-Trust Quarantine Initialization", tick())

    arduino = Device(
        device_id="dock-arduino-uno",
        mac_address="00:1A:79:AB:CD:01",
        physical_port=1,
        ip_address=None,  # Offline serial/USB device
    )
    print(f"  {tick()} 🔌 Physical insertion detected on Port 1: Arduino UNO (Atmega328P)")
    sys.stdout.flush()
    pace_pause(0.8)

    engine.register_device(arduino)
    audit_log.record(
        event_type=AuditEventType.DISCOVERY,
        reason_code="DOCK_ATTACHED",
        device_id=arduino.device_id,
        details={"port": 1, "model": "Arduino UNO"},
    )
    print(f"  {tick()} 🛡️  Enforcing Zero-Trust Isolation: {BOLD}{arduino.device_id}{RESET} -> {YELLOW}{registry.lookup('dock-arduino-uno').status.name}{RESET}")
    sys.stdout.flush()
    pace_pause(0.8)

    esp8266 = Device(
        device_id="dock-esp8266-wifi",
        mac_address="5C:CF:7F:4A:22:90",
        physical_port=2,
        ip_address="192.168.1.105",
    )
    print(f"\n  {tick()} 🔌 Physical insertion detected on Port 2: ESP8266 WiFi (Tensilica L106)")
    sys.stdout.flush()
    pace_pause(0.8)

    engine.register_device(esp8266)
    audit_log.record(
        event_type=AuditEventType.DISCOVERY,
        reason_code="DOCK_ATTACHED",
        device_id=esp8266.device_id,
        details={"port": 2, "model": "ESP8266 WiFi"},
    )
    print(f"  {tick()} 🌐 DHCP server leases IP 192.168.1.105 to MAC 5C:CF:7F:4A:22:90")
    print(f"  {tick()} 🛡️  Enforcing Zero-Trust Isolation: {BOLD}{esp8266.device_id}{RESET} -> {YELLOW}{registry.lookup('dock-esp8266-wifi').status.name}{RESET}")
    sys.stdout.flush()
    pace_pause(1.2)

    # --------------------------------------------------------------------------
    # STEP 2: Physical Telemetry Ingestion (INA3221 Sensor)
    # --------------------------------------------------------------------------
    print_step(2, "INA3221 Power Monitor Readings Ingestion", tick())
    now = time.time()

    print(f"  {tick()} ⚡ Polling INA3221 I2C Shunt Monitor (Port 1 - Arduino UNO)...")
    sys.stdout.flush()
    pace_pause(0.8)

    p_arduino = PhysicalTelemetry(
        device_id="dock-arduino-uno",
        physical_port=1,
        voltage_v=5.02,
        current_a=0.048,  # 48 mA
        temperature_c=28.5,
        timestamp=now,
    )
    validator = TelemetryValidator()
    assert validator.validate_physical(p_arduino).is_valid
    print(f"  {tick()}    Reading: Voltage: 5.02V | Current: {BOLD}48.0 mA{RESET} (0.24W) | Temp: 28.5°C -> {GREEN}COMPLIANT{RESET}")
    sys.stdout.flush()
    pace_pause(0.8)

    print(f"  {tick()} ⚡ Polling INA3221 I2C Shunt Monitor (Port 2 - ESP8266 WiFi)...")
    sys.stdout.flush()
    pace_pause(0.8)

    p_esp8266 = PhysicalTelemetry(
        device_id="dock-esp8266-wifi",
        physical_port=2,
        voltage_v=5.01,
        current_a=0.092,  # 92 mA (benign power draw!)
        temperature_c=34.2,
        timestamp=now,
    )
    assert validator.validate_physical(p_esp8266).is_valid
    print(f"  {tick()}    Reading: Voltage: 5.01V | Current: {BOLD}92.0 mA{RESET} (0.46W) | Temp: 34.2°C -> {GREEN}COMPLIANT{RESET}")
    print(f"\n  {CYAN}Hardware Insight:{RESET} Both devices draw completely nominal low-voltage bench power.")
    sys.stdout.flush()
    pace_pause(1.2)

    # --------------------------------------------------------------------------
    # STEP 3: Initial Admission Evaluation
    # --------------------------------------------------------------------------
    print_step(3, "Initial Admission Evaluation", tick())

    print(f"  {tick()} ⚖️  Evaluating admission criteria for dock-arduino-uno...")
    sys.stdout.flush()
    pace_pause(0.8)

    decision_arduino = engine.evaluate_admission("dock-arduino-uno", physical_telemetry=[p_arduino])
    print(f"  {tick()} • Arduino UNO Verdict: {YELLOW}{decision_arduino.decision_type.value}{RESET}")
    print(f"    - State: {registry.lookup('dock-arduino-uno').status.name}")
    print(f"    - Reason: {decision_arduino.explanation}")
    audit_log.record(
        event_type=AuditEventType.POLICY_DECISION,
        reason_code="ADMISSION_EVALUATION",
        device_id="dock-arduino-uno",
        details={"verdict": decision_arduino.decision_type.value, "reason": decision_arduino.explanation},
    )
    sys.stdout.flush()
    pace_pause(0.8)

    print(f"\n  {tick()} ⚖️  Evaluating admission criteria for dock-esp8266-wifi...")
    sys.stdout.flush()
    pace_pause(0.8)

    n_baseline = NetworkTelemetry(
        source_mac="5C:CF:7F:4A:22:90",
        source_ip="192.168.1.105",
        destination="192.168.1.1",
        protocol="UDP",
        source_port=51240,
        destination_port=53,
        packet_count=2,
        byte_count=168,
        timestamp=now,
        device_id="dock-esp8266-wifi",
        physical_port=2,
        app_protocol="DNS",
        tls_cert_valid=None,
    )

    decision_esp = engine.evaluate_admission(
        "dock-esp8266-wifi",
        physical_telemetry=[p_esp8266],
        network_telemetry=[n_baseline],
    )
    print(f"  {tick()} • ESP8266 Verdict: {GREEN}{decision_esp.decision_type.value}{RESET}")
    print(f"    - State Transition: QUARANTINED -> {GREEN}{registry.lookup('dock-esp8266-wifi').status.name}{RESET}")
    print(f"    - Reason: {decision_esp.explanation}")
    audit_log.record(
        event_type=AuditEventType.POLICY_DECISION,
        reason_code="ADMISSION_EVALUATION",
        device_id="dock-esp8266-wifi",
        details={"verdict": decision_esp.decision_type.value, "reason": decision_esp.explanation},
    )
    audit_log.record(
        event_type=AuditEventType.STATE_TRANSITION,
        reason_code="ADMISSION_ADMITTED",
        device_id="dock-esp8266-wifi",
        details={"from": "QUARANTINED", "to": "TRUSTED"},
    )
    sys.stdout.flush()
    pace_pause(1.2)

    # --------------------------------------------------------------------------
    # STEP 4: Real-Time Application Layer Protocol Inspection
    # --------------------------------------------------------------------------
    print_step(4, "Raspberry Pi Network Inspection: Application Layer Protocols", tick())
    print("The Raspberry Pi passively inspects live network traffic across gateway routing:\n")
    print(f"{BOLD}{'TIME':<10} | {'FLOW':<6} | {'APP PROTOCOL':<13} | {'SRC IP:PORT':<22} | {'DEST IP:PORT':<22} | {'CERT STATUS':<16} | {'STATUS':<10}{RESET}")
    print("-" * 109)
    sys.stdout.flush()
    pace_pause(0.5)

    # Flow 1: DNS Query
    print(f"{tick():<10} | Flow 1 | {CYAN}DNS{RESET}          | 192.168.1.105:51240    | 192.168.1.1:53 (Pi DNS)    | N/A (Plain UDP)  | {GREEN}ALLOWED{RESET}")
    sys.stdout.flush()
    pace_pause(0.7)

    # Flow 2: NTP Time Sync
    n_ntp = NetworkTelemetry(
        source_mac="5C:CF:7F:4A:22:90",
        source_ip="192.168.1.105",
        destination="192.168.1.1",
        protocol="UDP",
        source_port=49152,
        destination_port=123,
        packet_count=4,
        byte_count=192,
        timestamp=now + 1.0,
        device_id="dock-esp8266-wifi",
        physical_port=2,
        app_protocol="NTP",
        tls_cert_valid=None,
    )
    print(f"{tick():<10} | Flow 2 | {CYAN}NTP{RESET}          | 192.168.1.105:49152    | 192.168.1.1:123 (Pi Time)  | N/A (Plain UDP)  | {GREEN}ALLOWED{RESET}")
    sys.stdout.flush()
    pace_pause(0.7)

    # Flow 3: Internal MQTT Telemetry
    n_mqtt = NetworkTelemetry(
        source_mac="5C:CF:7F:4A:22:90",
        source_ip="192.168.1.105",
        destination="192.168.1.10",
        protocol="TCP",
        source_port=40122,
        destination_port=1883,
        packet_count=12,
        byte_count=840,
        timestamp=now + 2.0,
        device_id="dock-esp8266-wifi",
        physical_port=2,
        app_protocol="MQTT",
        tls_cert_valid=None,
    )
    print(f"{tick():<10} | Flow 3 | {CYAN}MQTT{RESET}         | 192.168.1.105:40122    | 192.168.1.10:1883 (Broker) | N/A (Plain TCP)  | {GREEN}ALLOWED{RESET}")
    sys.stdout.flush()
    pace_pause(0.7)

    # Flow 4: Legitimate HTTPS Firmware Check (Valid Certificate)
    n_https_valid = NetworkTelemetry(
        source_mac="5C:CF:7F:4A:22:90",
        source_ip="192.168.1.105",
        destination="142.250.190.46",  # update.vendor.org
        protocol="TCP",
        source_port=43210,
        destination_port=443,
        packet_count=20,
        byte_count=2400,
        timestamp=now + 3.0,
        device_id="dock-esp8266-wifi",
        physical_port=2,
        app_protocol="HTTPS",
        tls_cert_valid=True,
        tls_cert_error=None,
    )
    print(f"{tick():<10} | Flow 4 | {CYAN}HTTPS{RESET}        | 192.168.1.105:43210    | 142.250.190.46:443 (OTA)   | {GREEN}VALID (CA OK){RESET}    | {GREEN}ALLOWED{RESET}")
    sys.stdout.flush()
    pace_pause(0.7)

    # Flow 5: Rogue Outbound Connection (INVALID CERTIFICATE / UNTRUSTED CA)
    n_https_rogue = NetworkTelemetry(
        source_mac="5C:CF:7F:4A:22:90",
        source_ip="192.168.1.105",
        destination="198.51.100.77",  # Suspicious External Host
        protocol="TCP",
        source_port=48999,
        destination_port=8443,
        packet_count=8,
        byte_count=980,
        timestamp=now + 4.0,
        device_id="dock-esp8266-wifi",
        physical_port=2,
        app_protocol="HTTPS/C2",
        tls_cert_valid=False,  # INVALID CERTIFICATE DETECTED!
        tls_cert_error="EXPIRED_AND_SELF_SIGNED_UNTRUSTED_ISSUER",
    )
    print(f"{tick():<10} | Flow 5 | {RED}HTTPS/C2{RESET}     | 192.168.1.105:48999    | 198.51.100.77:8443 (Rogue) | {RED}INVALID (EXPIRED){RESET} | {RED}VIOLATION{RESET}")
    sys.stdout.flush()
    pace_pause(0.5)

    print(f"\n  {RED}⚠️  [REAL-TIME ALERT]{RESET} Gateway intercepted TLS handshake on port 8443 with untrusted root!")
    print(f"      Certificate Status: {RED}EXPIRED_AND_SELF_SIGNED_UNTRUSTED_ISSUER{RESET}")
    sys.stdout.flush()
    pace_pause(0.8)

    # Physical telemetry at the exact moment of Flow 5
    p_esp8266_flow5 = PhysicalTelemetry(
        device_id="dock-esp8266-wifi",
        physical_port=2,
        voltage_v=5.00,
        current_a=0.095,  # Only 95mA! Completely nominal!
        temperature_c=34.6,
        timestamp=now + 4.0,
    )

    print(f"\n{BOLD}PHYSICAL POWER DRAW DURING ATTACK:{RESET}")
    print(f"  • INA3221 Measured Power: {p_esp8266_flow5.voltage_v:.2f}V, {p_esp8266_flow5.current_a*1000:.1f} mA (0.47W)")
    print(f"  • {YELLOW}CRITICAL OBSERVATION:{RESET} The ESP8266 is transmitting to an untrusted server, but its")
    print(f"    power draw stayed at a tiny 95mA! A hardware power monitor ALONE CANNOT detect this attack.")
    sys.stdout.flush()
    pace_pause(1.2)

    # --------------------------------------------------------------------------
    # STEP 5: Trust Engine Behavioral Evaluation & Decision
    # --------------------------------------------------------------------------
    print_step(5, "Trust Engine Decision & Automated Isolation", tick())

    print(f"  {tick()} 🚨 Correlating physical telemetry with application-layer evidence...")
    sys.stdout.flush()
    pace_pause(0.8)

    mon_decision = engine.evaluate_monitoring(
        device_id="dock-esp8266-wifi",
        physical_telemetry=[p_esp8266_flow5],
        network_telemetry=[n_ntp, n_mqtt, n_https_valid, n_https_rogue],
    )

    print(f"  {tick()} • Evaluation Verdict:       {RED}{BOLD}{mon_decision.decision_type.value}{RESET}")
    print(f"  {tick()} • Lifecycle State Change:   TRUSTED -> {RED}{BOLD}{registry.lookup('dock-esp8266-wifi').status.name}{RESET}")
    print(f"  {tick()} • Security Reason Code:     {YELLOW}{mon_decision.reason_codes[0]}{RESET}")
    print(f"  {tick()} • Forensic Explanation:     {mon_decision.explanation}")
    print(f"  {tick()} • TLS Certificate Failure:  {RED}{mon_decision.evidence_summary.get('tls_cert_error')}{RESET}")
    sys.stdout.flush()
    pace_pause(0.8)

    audit_log.record(
        event_type=AuditEventType.POLICY_DECISION,
        reason_code="MONITORING_EVALUATION",
        device_id="dock-esp8266-wifi",
        details={"verdict": mon_decision.decision_type.value, "reason": mon_decision.explanation},
    )
    audit_log.record(
        event_type=AuditEventType.STATE_TRANSITION,
        reason_code="ISOLATION_TRIGGERED",
        device_id="dock-esp8266-wifi",
        details={"from": "TRUSTED", "to": "ISOLATED", "tls_error": mon_decision.evidence_summary.get("tls_cert_error")},
    )

    print(f"\n  {tick()} 🔒 Dispatching automated isolation command to gateway...")
    sys.stdout.flush()
    pace_pause(0.8)

    # Trigger simulated enforcement
    enf_result = enforcement.isolate_device(
        device_id="dock-esp8266-wifi",
        reason=mon_decision.explanation,
    )
    print(f"  {tick()} • Enforcement Action:       {BOLD}{enf_result.action.value}{RESET} [{GREEN}SUCCESS (SIMULATED){RESET}]")
    print(f"  {tick()} • Enforcement Action Note:  {enf_result.reason}")
    sys.stdout.flush()
    pace_pause(1.0)

    # --------------------------------------------------------------------------
    # STEP 6: Final Bench Audit Summary
    # --------------------------------------------------------------------------
    print_step(6, "Final Bench Status & Audit Summary", tick())
    print(f"{BOLD}{'PORT':<6} | {'DEVICE ID':<22} | {'HARDWARE TYPE':<18} | {'CURRENT':<10} | {'FINAL TRUST STATE':<18}{RESET}")
    print("-" * 85)
    for dev in registry.list_devices():
        curr_str = "48 mA" if dev.device_id == "dock-arduino-uno" else "95 mA"
        hw_type = "Arduino UNO" if dev.device_id == "dock-arduino-uno" else "ESP8266 WiFi"
        state_color = GREEN if dev.status == DeviceState.TRUSTED else (YELLOW if dev.status == DeviceState.QUARANTINED else RED)
        print(f"Port {dev.physical_port:<2} | {dev.device_id:<22} | {hw_type:<18} | {curr_str:<10} | {state_color}{BOLD}{dev.status.name}{RESET}")

    print(f"\n{BOLD}Audit Trail Events Recorded:{RESET} {len(audit_log)}")
    for ev in audit_log.get_events():
        print(f"  [{ev.timestamp:.2f}] {ev.event_type.value:<18} | Dev: {ev.device_id or 'N/A':<20} | Reason: {ev.reason_code}")

    elapsed_total = time.monotonic() - t_start
    print_banner(f"SIMULATION COMPLETED SUCCESSFULLY IN {elapsed_total:.2f}s WITH DETERMINISTIC VERDICTS")
    return 0


def main() -> int:
    """Parse CLI arguments and run simulation."""
    parser = argparse.ArgumentParser(
        description="Smart Backplane Multi-Device Bench Real-Time Simulation (Arduino UNO & ESP8266 WiFi)"
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Run simulation instantly without pacing delays (recommended for automated tests & CI)",
    )
    parser.add_argument(
        "--pace",
        type=float,
        default=0.4,
        help="Delay multiplier in seconds between real-time events (default: 0.4s)",
    )
    args = parser.parse_args()

    pace = 0.0 if args.fast else args.pace
    return run_simulation(pace=pace)


if __name__ == "__main__":
    sys.exit(main())
