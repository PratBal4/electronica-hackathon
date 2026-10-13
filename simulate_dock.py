#!/usr/bin/env python3
"""Smart Backplane Trust Engine --- Multi-Device Bench Simulation.

Simulates a physical dual-device dock scenario:
1. Arduino UNO on Port 1:
   - Low idle power (~5.02V, ~0.048A / 48mA).
   - Generates zero network traffic (no WiFi interface).
2. ESP8266 with WiFi Module on Port 2:
   - Low, benign power draw (~5.01V, ~0.092A / 92mA) despite active radio.
   - Makes outbound network connections via Raspberry Pi gateway (192.168.1.1).
   - Interacts with Application Layer protocols: DNS, NTP, MQTT, and HTTPS.
   - Connects to an external destination (198.51.100.77:8443) with an INVALID TLS CERTIFICATE.
   - Demonstrates that physical power monitoring is blind to application-layer security threats.
   - Shows the Raspberry Pi's step-by-step decision to transition the ESP8266 from TRUSTED -> ISOLATED.
"""

from __future__ import annotations

import sys
import time
from typing import List

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
RESET = "\033[0m" if IS_TTY else ""


def print_banner(text: str) -> None:
    print(f"\n{BOLD}{CYAN}{'=' * 75}{RESET}")
    print(f"{BOLD}{CYAN}   {text}{RESET}")
    print(f"{BOLD}{CYAN}{'=' * 75}{RESET}\n")


def print_step(step_num: int, title: str) -> None:
    print(f"\n{BOLD}{YELLOW}[STEP {step_num}] {title}{RESET}")
    print("-" * 75)


def run_simulation() -> int:
    """Execute the Arduino UNO + ESP8266 multi-device dock simulation."""
    print_banner("SMART BACKPLANE --- ARDUINO & ESP8266 BENCH SIMULATION")

    print(f"{BOLD}NETWORK TOPOLOGY (Managed by Raspberry Pi Gateway):{RESET}")
    print(f"  • Raspberry Pi Gateway IP:     {BOLD}192.168.1.1{RESET} (Backplane Controller & Inspector)")
    print(f"  • Subnet:                      {BOLD}192.168.1.0/24{RESET}")
    print(f"  • Dock Port 1:                 {BOLD}Arduino UNO{RESET} (Offline Microcontroller, 00:1A:79:AB:CD:01)")
    print(f"  • Dock Port 2:                 {BOLD}ESP8266 WiFi{RESET} (DHCP IP: 192.168.1.105, MAC: 5C:CF:7F:4A:22:90)")
    print(f"  • Local Network Services:      DNS (192.168.1.1:53), NTP (192.168.1.1:123), MQTT (192.168.1.10:1883)")
    print("-" * 75)

    # Initialize Trust Engine components
    registry = DeviceRegistry()
    audit_log = AuditLog()
    enforcement = SimulatedEnforcementAdapter(registry=registry, audit_log=audit_log)
    policy_engine = PolicyEngine()
    engine = TrustEngine(registry=registry, policy_engine=policy_engine)

    # --------------------------------------------------------------------------
    # STEP 1: Device Docking & Zero-Trust Quarantine
    # --------------------------------------------------------------------------
    print_step(1, "Physical Docking & Zero-Trust Quarantine Initialization")

    arduino = Device(
        device_id="dock-arduino-uno",
        mac_address="00:1A:79:AB:CD:01",
        physical_port=1,
        ip_address=None,  # Offline serial/USB device
    )

    esp8266 = Device(
        device_id="dock-esp8266-wifi",
        mac_address="5C:CF:7F:4A:22:90",
        physical_port=2,
        ip_address="192.168.1.105",
    )

    engine.register_device(arduino)
    engine.register_device(esp8266)

    print(f"  • Device 1 Docked: {BOLD}{arduino.device_id}{RESET} on Port 1")
    print(f"    - Type: Arduino UNO (Atmega328P)")
    print(f"    - Initial Trust State: {YELLOW}{registry.lookup('dock-arduino-uno').status.name}{RESET}")

    print(f"\n  • Device 2 Docked: {BOLD}{esp8266.device_id}{RESET} on Port 2")
    print(f"    - Type: ESP8266 (Tensilica L106 with 802.11 b/g/n WiFi)")
    print(f"    - Assigned IP: 192.168.1.105")
    print(f"    - Initial Trust State: {YELLOW}{registry.lookup('dock-esp8266-wifi').status.name}{RESET}")

    audit_log.record(
        event_type=AuditEventType.DISCOVERY,
        reason_code="DOCK_ATTACHED",
        device_id=arduino.device_id,
        details={"port": 1, "model": "Arduino UNO"},
    )
    audit_log.record(
        event_type=AuditEventType.DISCOVERY,
        reason_code="DOCK_ATTACHED",
        device_id=esp8266.device_id,
        details={"port": 2, "model": "ESP8266 WiFi"},
    )

    # --------------------------------------------------------------------------
    # STEP 2: Physical Telemetry Ingestion (INA3221 Sensor)
    # --------------------------------------------------------------------------
    print_step(2, "INA3221 Power Monitor Readings Ingestion")
    now = time.time()

    # Arduino: nominal low power
    p_arduino = PhysicalTelemetry(
        device_id="dock-arduino-uno",
        physical_port=1,
        voltage_v=5.02,
        current_a=0.048,  # 48 mA
        temperature_c=28.5,
        timestamp=now,
    )

    # ESP8266: nominal low power (does not draw excessive current)
    p_esp8266 = PhysicalTelemetry(
        device_id="dock-esp8266-wifi",
        physical_port=2,
        voltage_v=5.01,
        current_a=0.092,  # 92 mA (benign power draw!)
        temperature_c=34.2,
        timestamp=now,
    )

    validator = TelemetryValidator()
    assert validator.validate_physical(p_arduino).is_valid
    assert validator.validate_physical(p_esp8266).is_valid

    print(f"  [Port 1 - Arduino UNO]  Voltage: {p_arduino.voltage_v:.2f}V | Current: {BOLD}{p_arduino.current_a*1000:.1f} mA{RESET} (0.24W) | Temp: {p_arduino.temperature_c}°C -> {GREEN}COMPLIANT{RESET}")
    print(f"  [Port 2 - ESP8266]      Voltage: {p_esp8266.voltage_v:.2f}V | Current: {BOLD}{p_esp8266.current_a*1000:.1f} mA{RESET} (0.46W) | Temp: {p_esp8266.temperature_c}°C -> {GREEN}COMPLIANT{RESET}")
    print(f"\n  {CYAN}Insight:{RESET} Both devices draw completely normal, healthy low-voltage dock power.")

    # --------------------------------------------------------------------------
    # STEP 3: Initial Admission Evaluation
    # --------------------------------------------------------------------------
    print_step(3, "Initial Admission Evaluation")

    # Arduino UNO has no network telemetry (it is an offline microcontroller)
    decision_arduino = engine.evaluate_admission("dock-arduino-uno", physical_telemetry=[p_arduino])
    print(f"  • Arduino UNO Verdict: {YELLOW}{decision_arduino.decision_type.value}{RESET}")
    print(f"    - State: {registry.lookup('dock-arduino-uno').status.name}")
    print(f"    - Reason: {decision_arduino.explanation}")

    # ESP8266 provides initial baseline network flow: local DNS query to Gateway
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
        tls_cert_valid=None,  # Plain UDP DNS, no TLS
    )

    decision_esp = engine.evaluate_admission(
        "dock-esp8266-wifi",
        physical_telemetry=[p_esp8266],
        network_telemetry=[n_baseline],
    )
    print(f"\n  • ESP8266 Verdict: {GREEN}{decision_esp.decision_type.value}{RESET}")
    print(f"    - State Transition: QUARANTINED -> {GREEN}{registry.lookup('dock-esp8266-wifi').status.name}{RESET}")
    print(f"    - Reason: {decision_esp.explanation}")
    audit_log.record(
        event_type=AuditEventType.POLICY_DECISION,
        reason_code="ADMISSION_EVALUATION",
        device_id="dock-arduino-uno",
        details={"verdict": decision_arduino.decision_type.value, "reason": decision_arduino.explanation},
    )
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

    # --------------------------------------------------------------------------
    # STEP 4: Network Observation & Application Layer Protocol Inspection
    # --------------------------------------------------------------------------
    print_step(4, "Raspberry Pi Network Inspection: Application Layer Protocols")
    print("The Raspberry Pi passively inspects network traffic passing through its interface:\n")
    print(f"{BOLD}{'FLOW':<6} | {'APP PROTOCOL':<13} | {'SRC IP:PORT':<22} | {'DEST IP:PORT':<22} | {'CERT STATUS':<16} | {'STATUS':<10}{RESET}")
    print("-" * 96)

    # Flow 1: DNS Query
    print(f"Flow 1 | {CYAN}DNS{RESET}          | 192.168.1.105:51240    | 192.168.1.1:53 (Pi DNS)    | N/A (Plain UDP)  | {GREEN}ALLOWED{RESET}")
    
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
    print(f"Flow 2 | {CYAN}NTP{RESET}          | 192.168.1.105:49152    | 192.168.1.1:123 (Pi Time)  | N/A (Plain UDP)  | {GREEN}ALLOWED{RESET}")

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
    print(f"Flow 3 | {CYAN}MQTT{RESET}         | 192.168.1.105:40122    | 192.168.1.10:1883 (Broker) | N/A (Plain TCP)  | {GREEN}ALLOWED{RESET}")

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
        tls_cert_valid=True,  # Valid TLS Certificate
        tls_cert_error=None,
    )
    print(f"Flow 4 | {CYAN}HTTPS{RESET}        | 192.168.1.105:43210    | 142.250.190.46:443 (OTA)   | {GREEN}VALID (CA OK){RESET}    | {GREEN}ALLOWED{RESET}")

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
    print(f"Flow 5 | {RED}HTTPS/C2{RESET}     | 192.168.1.105:48999    | 198.51.100.77:8443 (Rogue) | {RED}INVALID (EXPIRED){RESET} | {RED}VIOLATION{RESET}")

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

    # --------------------------------------------------------------------------
    # STEP 5: Trust Engine Behavioral Evaluation & Decision
    # --------------------------------------------------------------------------
    print_step(5, "Trust Engine Decision & Automated Isolation")

    mon_decision = engine.evaluate_monitoring(
        device_id="dock-esp8266-wifi",
        physical_telemetry=[p_esp8266_flow5],
        network_telemetry=[n_ntp, n_mqtt, n_https_valid, n_https_rogue],
    )

    print(f"  • Evaluation Verdict:       {RED}{BOLD}{mon_decision.decision_type.value}{RESET}")
    print(f"  • Lifecycle State Change:   TRUSTED -> {RED}{BOLD}{registry.lookup('dock-esp8266-wifi').status.name}{RESET}")
    print(f"  • Security Reason Code:     {YELLOW}{mon_decision.reason_codes[0]}{RESET}")
    print(f"  • Forensic Explanation:     {mon_decision.explanation}")
    print(f"  • TLS Certificate Failure:  {RED}{mon_decision.evidence_summary.get('tls_cert_error')}{RESET}")

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

    # Trigger simulated enforcement
    enf_result = enforcement.isolate_device(
        device_id="dock-esp8266-wifi",
        reason=mon_decision.explanation,
    )
    print(f"\n  • Enforcement Action:       {BOLD}{enf_result.action.value}{RESET} [{GREEN}SUCCESS (SIMULATED){RESET}]")
    print(f"  • Enforcement Action Note:  {enf_result.reason}")

    # --------------------------------------------------------------------------
    # STEP 6: Final Bench Audit Summary
    # --------------------------------------------------------------------------
    print_step(6, "Final Bench Status & Audit Summary")
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

    print_banner("SIMULATION COMPLETED SUCCESSFULLY WITH DETERMINISTIC VERDICTS")
    return 0


if __name__ == "__main__":
    sys.exit(run_simulation())
