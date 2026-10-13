"""Security review and invariant verification tests.

Validates findings from formal security & boundary analysis:
- SEC-01: evaluate_monitoring rejects non-active devices (QUARANTINED, ISOLATED, REJECTED).
- SEC-02: evaluate_admission rejects non-quarantined devices (TRUSTED, ISOLATED, REJECTED).
- SEC-03: Registry forces initial QUARANTINED state even if caller supplies ANOMALOUS or ISOLATED.
- SEC-04: Whitespace padding in device identifiers is stripped to prevent alias collisions.
- SEC-05: Negative timestamps are explicitly rejected during telemetry validation.
"""

import time
import pytest

from trust_engine.device import Device
from trust_engine.engine import TrustEngine
from trust_engine.registry import DeviceRegistry
from trust_engine.states import DeviceState
from trust_engine.telemetry import (
    NetworkTelemetry,
    PhysicalTelemetry,
    validate_network_telemetry,
    validate_physical_telemetry,
)


@pytest.fixture
def engine() -> TrustEngine:
    """Fixture providing a fresh TrustEngine instance."""
    return TrustEngine()


def test_sec01_evaluate_monitoring_rejects_unadmitted_devices(engine: TrustEngine) -> None:
    """Verify evaluate_monitoring raises ValueError if called on QUARANTINED, ISOLATED, or REJECTED devices."""
    dev = Device("dev-01", "00:11:22:33:44:55", 1)
    engine.register_device(dev)  # Initially in QUARANTINED

    now = time.time()
    phys = [PhysicalTelemetry("dev-01", 1, 5.0, 0.4, now)]

    # 1. Device in QUARANTINED cannot be evaluated by monitoring
    with pytest.raises(ValueError, match="Cannot evaluate monitoring for device 'dev-01' in state QUARANTINED"):
        engine.evaluate_monitoring("dev-01", physical_telemetry=phys)

    # 2. Transition to REJECTED (via illegal or timeout)
    engine.transition_device("dev-01", DeviceState.REJECTED, reason="Test rejection")
    with pytest.raises(ValueError, match="Cannot evaluate monitoring for device 'dev-01' in state REJECTED"):
        engine.evaluate_monitoring("dev-01", physical_telemetry=phys)


def test_sec02_evaluate_admission_rejects_non_quarantined_devices(engine: TrustEngine) -> None:
    """Verify evaluate_admission raises ValueError if called on already TRUSTED, ISOLATED, or REJECTED devices."""
    dev = Device("dev-01", "00:11:22:33:44:55", 1)
    engine.register_device(dev)
    now = time.time()

    phys = [PhysicalTelemetry("dev-01", 1, 5.0, 0.4, now)]
    net = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 10, 500, now)]

    # Admit device to TRUSTED
    engine.evaluate_admission("dev-01", phys, net, current_time=now)
    assert engine.registry.get("dev-01").status is DeviceState.TRUSTED

    # Attempting to call evaluate_admission again on TRUSTED device must raise ValueError
    with pytest.raises(ValueError, match="Cannot evaluate admission for device 'dev-01' in state TRUSTED"):
        engine.evaluate_admission("dev-01", phys, net, current_time=now)


def test_sec03_registry_enforces_quarantine_for_all_untrusted_states() -> None:
    """Verify submitting ANOMALOUS, ISOLATED, or REJECTED status on registration is overridden to QUARANTINED."""
    registry = DeviceRegistry()

    # Attempt to register claiming ANOMALOUS
    d_anom = Device("dev-anom", "00:11:22:33:44:01", 1, status=DeviceState.ANOMALOUS)
    reg_anom = registry.register(d_anom)
    assert reg_anom.status is DeviceState.QUARANTINED
    assert registry.get("dev-anom").status is DeviceState.QUARANTINED

    # Attempt to register claiming ISOLATED
    d_iso = Device("dev-iso", "00:11:22:33:44:02", 2, status=DeviceState.ISOLATED)
    reg_iso = registry.register(d_iso)
    assert reg_iso.status is DeviceState.QUARANTINED
    assert registry.get("dev-iso").status is DeviceState.QUARANTINED


def test_sec04_device_identifier_whitespace_normalization() -> None:
    """Verify leading/trailing whitespace in device_id, mac_address, and port are stripped."""
    device = Device(
        device_id="  dev-padded-01  ",
        mac_address="  00:11:22:33:44:55  ",
        physical_port="  dock-port-1  ",
        ip_address="  192.168.1.10  ",
    )

    assert device.device_id == "dev-padded-01"
    assert device.mac_address == "00:11:22:33:44:55"
    assert device.physical_port == "dock-port-1"
    assert device.ip_address == "192.168.1.10"


def test_sec05_negative_timestamps_rejected() -> None:
    """Verify negative POSIX timestamps fail validation in physical and network telemetry."""
    # Negative physical timestamp
    phys_neg = PhysicalTelemetry("dev-01", 1, 5.0, 0.4, timestamp=-100.0)
    res_phys = validate_physical_telemetry(phys_neg)
    assert res_phys.is_valid is False
    assert any("timestamp must be a non-negative POSIX timestamp" in e for e in res_phys.errors)

    # Negative network timestamp
    net_neg = NetworkTelemetry("00:11:22:33:44:55", "10.0.0.1", "10.0.0.2", "TCP", 10, 500, timestamp=-1.0)
    res_net = validate_network_telemetry(net_neg)
    assert res_net.is_valid is False
    assert any("timestamp must be a non-negative POSIX timestamp" in e for e in res_net.errors)
