"""Tests for Multi-Device Bench Simulation (Arduino UNO & ESP8266 WiFi).

Verifies:
1. Physical dock registration of 2 devices (Arduino UNO and ESP8266).
2. Physical power blindness: ESP8266 draws benign current (~92-95mA) while communicating.
3. Multi-protocol application layer telemetry (DNS, NTP, MQTT, HTTPS).
4. Invalid TLS certificate detection on dummy IP triggering SEVERE_VIOLATION_INVALID_CERTIFICATE.
5. Deterministic isolation lifecycle transition from TRUSTED -> ISOLATED.
6. Execution of simulate_dock.py end-to-end.
"""

import time
import pytest
from trust_engine.audit import AuditEventType, AuditLog
from trust_engine.device import Device
from trust_engine.engine import TrustEngine
from trust_engine.enforcement import SimulatedEnforcementAdapter
from trust_engine.policy import DecisionType, PolicyEngine
from trust_engine.registry import DeviceRegistry
from trust_engine.states import DeviceState
from trust_engine.telemetry import NetworkTelemetry, PhysicalTelemetry
from simulate_dock import run_simulation


@pytest.fixture
def test_dock_setup():
    """Set up an isolated bench dock with registry, audit log, engine, and simulated enforcement."""
    registry = DeviceRegistry()
    audit_log = AuditLog()
    policy_engine = PolicyEngine()
    enforcement = SimulatedEnforcementAdapter(registry=registry, audit_log=audit_log)
    engine = TrustEngine(registry=registry, policy_engine=policy_engine)
    return registry, audit_log, engine, enforcement


def test_dock_two_devices_initial_quarantine(test_dock_setup):
    """Verify Arduino UNO and ESP8266 both dock in QUARANTINED state."""
    registry, audit_log, engine, _ = test_dock_setup

    arduino = Device(
        device_id="dock-arduino-uno",
        mac_address="00:1A:79:AB:CD:01",
        physical_port=1,
        ip_address=None,
    )
    esp8266 = Device(
        device_id="dock-esp8266-wifi",
        mac_address="5C:CF:7F:4A:22:90",
        physical_port=2,
        ip_address="192.168.1.105",
    )

    reg_uno = engine.register_device(arduino)
    reg_esp = engine.register_device(esp8266)

    assert reg_uno.status == DeviceState.QUARANTINED
    assert reg_esp.status == DeviceState.QUARANTINED
    assert len(registry.list_devices()) == 2


def test_arduino_uno_offline_remains_quarantined(test_dock_setup):
    """Verify Arduino UNO with low power and no network evidence remains QUARANTINED."""
    registry, _, engine, _ = test_dock_setup

    arduino = Device(
        device_id="dock-arduino-uno",
        mac_address="00:1A:79:AB:CD:01",
        physical_port=1,
    )
    engine.register_device(arduino)

    p_uno = PhysicalTelemetry(
        device_id="dock-arduino-uno",
        physical_port=1,
        voltage_v=5.02,
        current_a=0.048,
        temperature_c=28.5,
        timestamp=time.time(),
    )

    decision = engine.evaluate_admission(
        device_id="dock-arduino-uno",
        physical_telemetry=[p_uno],
        network_telemetry=[],  # No network telemetry (offline)
    )

    assert decision.decision_type == DecisionType.KEEP_QUARANTINED
    assert registry.lookup("dock-arduino-uno").status == DeviceState.QUARANTINED


def test_esp8266_benign_admission(test_dock_setup):
    """Verify ESP8266 with normal power (<100mA) and valid baseline DNS admits to TRUSTED."""
    registry, _, engine, _ = test_dock_setup

    esp8266 = Device(
        device_id="dock-esp8266-wifi",
        mac_address="5C:CF:7F:4A:22:90",
        physical_port=2,
        ip_address="192.168.1.105",
    )
    engine.register_device(esp8266)

    now = time.time()
    p_esp = PhysicalTelemetry(
        device_id="dock-esp8266-wifi",
        physical_port=2,
        voltage_v=5.01,
        current_a=0.092,  # 92 mA benign power
        temperature_c=34.2,
        timestamp=now,
    )
    n_dns = NetworkTelemetry(
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

    decision = engine.evaluate_admission(
        device_id="dock-esp8266-wifi",
        physical_telemetry=[p_esp],
        network_telemetry=[n_dns],
    )

    assert decision.decision_type == DecisionType.ALLOW
    assert registry.lookup("dock-esp8266-wifi").status == DeviceState.TRUSTED


def test_esp8266_invalid_tls_cert_triggers_isolation(test_dock_setup):
    """Demonstrate physical power blindness and isolation on invalid TLS certificate."""
    registry, audit_log, engine, enforcement = test_dock_setup

    esp8266 = Device(
        device_id="dock-esp8266-wifi",
        mac_address="5C:CF:7F:4A:22:90",
        physical_port=2,
        ip_address="192.168.1.105",
    )
    engine.register_device(esp8266)

    now = time.time()
    p_esp = PhysicalTelemetry(
        device_id="dock-esp8266-wifi",
        physical_port=2,
        voltage_v=5.01,
        current_a=0.092,
        temperature_c=34.2,
        timestamp=now,
    )
    n_dns = NetworkTelemetry(
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
    )
    # Step 1: Admit
    engine.evaluate_admission("dock-esp8266-wifi", [p_esp], [n_dns])
    assert registry.lookup("dock-esp8266-wifi").status == DeviceState.TRUSTED

    # Step 2: Benign power during rogue connection
    p_rogue = PhysicalTelemetry(
        device_id="dock-esp8266-wifi",
        physical_port=2,
        voltage_v=5.00,
        current_a=0.095,  # Benign 95mA current!
        temperature_c=34.6,
        timestamp=now + 5.0,
    )

    # Rogue connection with invalid TLS certificate to dummy IP
    n_rogue = NetworkTelemetry(
        source_mac="5C:CF:7F:4A:22:90",
        source_ip="192.168.1.105",
        destination="198.51.100.77",
        protocol="TCP",
        source_port=48999,
        destination_port=8443,
        packet_count=18,
        byte_count=2400,
        timestamp=now + 5.0,
        device_id="dock-esp8266-wifi",
        physical_port=2,
        app_protocol="HTTPS/C2",
        tls_cert_valid=False,
        tls_cert_error="EXPIRED_AND_SELF_SIGNED_UNTRUSTED_ISSUER",
    )

    decision = engine.evaluate_monitoring(
        device_id="dock-esp8266-wifi",
        physical_telemetry=[p_rogue],
        network_telemetry=[n_rogue],
    )

    assert decision.decision_type == DecisionType.ISOLATE
    assert "SEVERE_VIOLATION_INVALID_CERTIFICATE" in decision.reason_codes
    assert registry.lookup("dock-esp8266-wifi").status == DeviceState.ISOLATED

    # Simulated enforcement
    enf = enforcement.isolate_device("dock-esp8266-wifi", reason=decision.explanation)
    assert enf.success is True
    assert enf.is_simulation is True
    assert "simulated_enforcement" in enf.details


def test_esp8266_valid_tls_cert_remains_trusted(test_dock_setup):
    """Verify that a valid TLS certificate connection does not trigger isolation."""
    registry, _, engine, _ = test_dock_setup

    esp8266 = Device(
        device_id="dock-esp8266-wifi",
        mac_address="5C:CF:7F:4A:22:90",
        physical_port=2,
        ip_address="192.168.1.105",
    )
    engine.register_device(esp8266)

    now = time.time()
    p_esp = PhysicalTelemetry(
        device_id="dock-esp8266-wifi",
        physical_port=2,
        voltage_v=5.01,
        current_a=0.092,
        temperature_c=34.2,
        timestamp=now,
    )
    n_dns = NetworkTelemetry(
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
    )
    engine.evaluate_admission("dock-esp8266-wifi", [p_esp], [n_dns])

    # Valid HTTPS telemetry
    n_https = NetworkTelemetry(
        source_mac="5C:CF:7F:4A:22:90",
        source_ip="192.168.1.105",
        destination="142.250.190.46",
        protocol="TCP",
        source_port=43210,
        destination_port=443,
        packet_count=12,
        byte_count=1850,
        timestamp=now + 2.0,
        device_id="dock-esp8266-wifi",
        physical_port=2,
        app_protocol="HTTPS",
        tls_cert_valid=True,
    )

    decision = engine.evaluate_monitoring(
        device_id="dock-esp8266-wifi",
        physical_telemetry=[p_esp],
        network_telemetry=[n_https],
    )

    assert decision.decision_type == DecisionType.ALLOW
    assert registry.lookup("dock-esp8266-wifi").status == DeviceState.TRUSTED


def test_simulate_dock_script_end_to_end():
    """Verify simulate_dock.py executes cleanly end-to-end with zero errors."""
    exit_code = run_simulation()
    assert exit_code == 0
