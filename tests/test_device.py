"""Tests for the Device dataclass model."""

import pytest
from trust_engine.device import Device
from trust_engine.states import DeviceState


def test_device_creation_with_defaults() -> None:
    """Verify Device creates successfully with required fields and correct defaults."""
    device = Device(
        device_id="dev-001",
        mac_address="00:11:22:33:44:55",
        physical_port=1,
    )

    assert device.device_id == "dev-001"
    assert device.mac_address == "00:11:22:33:44:55"
    assert device.physical_port == 1
    assert device.ip_address is None
    assert device.status is DeviceState.QUARANTINED


def test_device_creation_with_all_fields() -> None:
    """Verify Device creates with all optional fields and string port."""
    device = Device(
        device_id="dev-002",
        mac_address="AA:BB:CC:DD:EE:FF",
        physical_port="dock-port-2",
        ip_address="192.168.1.50",
        status=DeviceState.UNKNOWN,
    )

    assert device.device_id == "dev-002"
    assert device.mac_address == "AA:BB:CC:DD:EE:FF"
    assert device.physical_port == "dock-port-2"
    assert device.ip_address == "192.168.1.50"
    assert device.status is DeviceState.UNKNOWN


def test_devices_have_independent_state() -> None:
    """Verify two Device instances maintain independent per-instance state without shared state."""
    dev1 = Device(
        device_id="dev-001",
        mac_address="00:11:22:33:44:55",
        physical_port=1,
        status=DeviceState.QUARANTINED,
    )
    dev2 = Device(
        device_id="dev-002",
        mac_address="AA:BB:CC:DD:EE:FF",
        physical_port=2,
        status=DeviceState.QUARANTINED,
    )

    # Mutate dev1
    dev1.status = DeviceState.TRUSTED
    dev1.ip_address = "10.0.0.10"

    # Verify dev2 is completely unaffected
    assert dev2.status is DeviceState.QUARANTINED
    assert dev2.ip_address is None
    assert dev1.status is DeviceState.TRUSTED

    # Ensure separate attribute dictionaries
    assert dev1.__dict__ is not dev2.__dict__


def test_device_status_string_normalization() -> None:
    """Verify string status passed to Device constructor is normalized to DeviceState."""
    device = Device(
        device_id="dev-003",
        mac_address="00:11:22:33:44:77",
        physical_port=3,
        status="anomalous",  # type: ignore
    )
    assert device.status is DeviceState.ANOMALOUS


def test_device_validation_errors() -> None:
    """Verify validation triggers on invalid fields."""
    with pytest.raises(ValueError, match="device_id must be a non-empty string"):
        Device(device_id="", mac_address="00:11:22:33:44:55", physical_port=1)

    with pytest.raises(ValueError, match="device_id must be a non-empty string"):
        Device(device_id=None, mac_address="00:11:22:33:44:55", physical_port=1)  # type: ignore

    with pytest.raises(ValueError, match="mac_address must be a non-empty string"):
        Device(device_id="dev-1", mac_address="   ", physical_port=1)

    with pytest.raises(ValueError, match="physical_port"):
        Device(device_id="dev-1", mac_address="00:11:22:33:44:55", physical_port="")

    with pytest.raises(ValueError, match="physical_port"):
        Device(device_id="dev-1", mac_address="00:11:22:33:44:55", physical_port=None)  # type: ignore

    with pytest.raises(ValueError, match="ip_address must be None or a non-empty string"):
        Device(device_id="dev-1", mac_address="00:11:22:33:44:55", physical_port=1, ip_address="")

    with pytest.raises(ValueError):
        Device(device_id="dev-1", mac_address="00:11:22:33:44:55", physical_port=1, status="NON_EXISTENT")


def test_device_to_dict() -> None:
    """Verify to_dict serialization produces expected dictionary structure."""
    device = Device(
        device_id="dev-001",
        mac_address="00:11:22:33:44:55",
        physical_port=1,
        ip_address="192.168.1.20",
        status=DeviceState.QUARANTINED,
    )
    data = device.to_dict()
    assert data == {
        "device_id": "dev-001",
        "mac_address": "00:11:22:33:44:55",
        "physical_port": 1,
        "ip_address": "192.168.1.20",
        "status": "QUARANTINED",
    }
