"""Tests for DeviceRegistry in-memory registry."""

import pytest
from trust_engine.device import Device
from trust_engine.registry import (
    DeviceConflictError,
    DeviceNotFoundError,
    DeviceRegistry,
    DuplicateDeviceError,
)
from trust_engine.states import DeviceState


@pytest.fixture
def registry() -> DeviceRegistry:
    """Fixture providing a fresh in-memory DeviceRegistry instance."""
    return DeviceRegistry()


def test_unique_registration_succeeds(registry: DeviceRegistry) -> None:
    """Verify registering new unique devices succeeds and stores records correctly."""
    dev = Device(device_id="dev-001", mac_address="00:11:22:33:44:55", physical_port=1)
    registered = registry.register(dev)

    assert registered.device_id == "dev-001"
    assert registered.mac_address == "00:11:22:33:44:55"
    assert registered.physical_port == 1
    assert registered.status is DeviceState.QUARANTINED
    assert len(registry) == 1
    assert "dev-001" in registry


def test_duplicate_id_fails_without_overwrite(registry: DeviceRegistry) -> None:
    """Verify duplicate device_id registration raises DuplicateDeviceError and does not overwrite existing record."""
    initial_device = Device(
        device_id="dev-001",
        mac_address="00:11:22:33:44:55",
        physical_port=1,
        ip_address="192.168.1.10",
        status=DeviceState.QUARANTINED,
    )
    registry.register(initial_device)

    # Attempt to register another device with identical device_id but different attributes
    colliding_device = Device(
        device_id="dev-001",
        mac_address="AA:BB:CC:DD:EE:FF",
        physical_port=2,
        ip_address="10.0.0.99",
        status=DeviceState.ANOMALOUS,
    )

    with pytest.raises(DuplicateDeviceError, match="is already registered"):
        registry.register(colliding_device)

    # CRITICAL CHECK: Ensure existing record is completely unchanged
    stored = registry.get("dev-001")
    assert stored is not None
    assert stored.mac_address == "00:11:22:33:44:55"
    assert stored.physical_port == 1
    assert stored.ip_address == "192.168.1.10"
    assert stored.status is DeviceState.QUARANTINED
    assert len(registry) == 1


def test_missing_id_lookup_behaviour(registry: DeviceRegistry) -> None:
    """Verify defined behaviour for missing-ID lookups.

    - registry.get() returns None (or specified default) safely.
    - registry.lookup() raises DeviceNotFoundError (and KeyError).
    - registry['missing'] raises DeviceNotFoundError (and KeyError).
    - 'missing' in registry evaluates to False.
    """
    assert "non-existent" not in registry

    # 1. get() returns None by default without raising
    assert registry.get("non-existent") is None

    # 2. get() returns custom default if provided
    default_dev = Device(device_id="def", mac_address="00:00:00:00:00:00", physical_port=0)
    assert registry.get("non-existent", default=default_dev) == default_dev

    # 3. lookup() strictly raises DeviceNotFoundError
    with pytest.raises(DeviceNotFoundError, match="was not found in the registry"):
        registry.lookup("non-existent")

    # 4. Dictionary index access raises DeviceNotFoundError
    with pytest.raises(DeviceNotFoundError):
        _ = registry["non-existent"]

    # 5. DeviceNotFoundError is also a KeyError subclass for dict compatibility
    with pytest.raises(KeyError):
        registry.lookup("non-existent")


def test_device_supplied_trusted_status_is_rejected_and_quarantined(registry: DeviceRegistry) -> None:
    """Verify registry enforces status ownership and refuses device-supplied TRUSTED state.

    Never trust a device-supplied status field or allow it to set itself TRUSTED.
    """
    untrusted_payload = Device(
        device_id="rogue-001",
        mac_address="DE:AD:BE:EF:00:01",
        physical_port=1,
        status=DeviceState.TRUSTED,  # Device tries claiming it is TRUSTED
    )

    registered = registry.register(untrusted_payload)

    # Must be quarantined upon admission, NOT trusted
    assert registered.status is not DeviceState.TRUSTED
    assert registered.status is DeviceState.QUARANTINED

    stored = registry.get("rogue-001")
    assert stored is not None
    assert stored.status is DeviceState.QUARANTINED


def test_registry_defensive_copies_prevent_external_tampering(registry: DeviceRegistry) -> None:
    """Verify external caller mutating a Device instance does not mutate registry state."""
    device = Device(
        device_id="dev-001",
        mac_address="00:11:22:33:44:55",
        physical_port=1,
        status=DeviceState.QUARANTINED,
    )
    registry.register(device)

    # 1. Mutate the original device object passed into register()
    device.status = DeviceState.TRUSTED
    assert registry.get("dev-001").status is DeviceState.QUARANTINED

    # 2. Mutate the device object returned by get()
    fetched = registry.get("dev-001")
    assert fetched is not None
    fetched.status = DeviceState.TRUSTED
    assert registry.get("dev-001").status is DeviceState.QUARANTINED

    # 3. Mutate the device object returned by lookup()
    looked_up = registry.lookup("dev-001")
    looked_up.status = DeviceState.TRUSTED
    assert registry.get("dev-001").status is DeviceState.QUARANTINED


def test_authoritative_status_update(registry: DeviceRegistry) -> None:
    """Verify engine/registry-owned update_status transitions device state authoritatively."""
    dev = Device(device_id="dev-001", mac_address="00:11:22:33:44:55", physical_port=1)
    registry.register(dev)

    # Transition to TRUSTED via authoritative method
    updated = registry.update_status("dev-001", DeviceState.TRUSTED)
    assert updated.status is DeviceState.TRUSTED
    assert registry.get("dev-001").status is DeviceState.TRUSTED

    # Transition to ANOMALOUS using string
    updated2 = registry.update_status("dev-001", "ANOMALOUS")
    assert updated2.status is DeviceState.ANOMALOUS

    # Attempt updating non-existent device
    with pytest.raises(DeviceNotFoundError):
        registry.update_status("missing-dev", DeviceState.TRUSTED)

    # Attempt updating with invalid state
    with pytest.raises(ValueError):
        registry.update_status("dev-001", "INVALID_STATE")


def test_mac_and_port_conflict_detection(registry: DeviceRegistry) -> None:
    """Verify conflicts on physical port and MAC address are detected and flagged."""
    dev1 = Device(device_id="dev-001", mac_address="00:11:22:33:44:55", physical_port=1)
    registry.register(dev1)

    # Conflicting device on same physical port
    port_conflict_dev = Device(
        device_id="dev-002",
        mac_address="AA:BB:CC:DD:EE:FF",
        physical_port=1,
    )
    conflicts = registry.check_conflicts(port_conflict_dev)
    assert len(conflicts) == 1
    assert "Port conflict" in conflicts[0]

    # Conflicting device with same MAC address on different port
    mac_conflict_dev = Device(
        device_id="dev-003",
        mac_address="00:11:22:33:44:55",
        physical_port=2,
    )
    conflicts = registry.check_conflicts(mac_conflict_dev)
    assert len(conflicts) == 1
    assert "MAC conflict" in conflicts[0]

    # Registration with reject_conflicts=True raises DeviceConflictError
    with pytest.raises(DeviceConflictError, match="Registration rejected due to conflicts"):
        registry.register(port_conflict_dev, reject_conflicts=True)


def test_list_and_iteration(registry: DeviceRegistry) -> None:
    """Verify list_devices, clear, iteration, and len work correctly."""
    dev1 = Device(device_id="dev-001", mac_address="00:11:22:33:44:55", physical_port=1)
    dev2 = Device(device_id="dev-002", mac_address="AA:BB:CC:DD:EE:FF", physical_port=2)
    registry.register(dev1)
    registry.register(dev2)

    assert len(registry) == 2
    assert list(registry) == ["dev-001", "dev-002"]

    all_devs = registry.list_devices()
    assert len(all_devs) == 2
    assert {d.device_id for d in all_devs} == {"dev-001", "dev-002"}

    registry.clear()
    assert len(registry) == 0
    assert registry.get("dev-001") is None
