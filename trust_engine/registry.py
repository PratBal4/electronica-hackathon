"""In-memory device registry for the Smart Backplane Trust Engine.

Authoritatively tracks docked devices by device_id. Manages trust status ownership,
prevents duplicate ID collisions without overwriting existing records, and flags
MAC/port binding conflicts.
"""

from copy import replace
from dataclasses import replace as dataclass_replace
import logging
from typing import Dict, Iterator, List, Optional, Union

from trust_engine.device import Device
from trust_engine.states import DeviceState

logger = logging.getLogger(__name__)


class RegistryError(Exception):
    """Base exception for device registry operations."""


class DuplicateDeviceError(RegistryError):
    """Raised when attempting to register a device with an ID that already exists."""


class DeviceNotFoundError(RegistryError, KeyError):
    """Raised when looking up a device ID that does not exist in the registry."""


class DeviceConflictError(RegistryError):
    """Raised when a device registration conflicts with an existing port or MAC binding."""


class DeviceRegistry:
    """Authoritative in-memory registry for docked devices.

    The registry is keyed by device_id. It owns the trust status lifecycle:
    device-supplied statuses of TRUSTED are rejected/quarantined upon registration,
    and all records are stored and retrieved defensively to prevent external mutations.
    """

    def __init__(self) -> None:
        """Initialize an empty in-memory registry."""
        self._devices: Dict[str, Device] = {}

    def register(self, device: Device, reject_conflicts: bool = False) -> Device:
        """Register a new device into the in-memory registry.

        Requirements:
        1. Duplicate IDs must fail clearly with DuplicateDeviceError and never
           overwrite the existing record.
        2. Trust status is owned strictly by the engine/registry: an untrusted device
           payload cannot set itself to TRUSTED. If status is TRUSTED, it is forced
           to QUARANTINED.
        3. Stored records are defensive copies so callers cannot mutate internal state.

        Args:
            device: The Device instance to register.
            reject_conflicts: If True, raise DeviceConflictError if the physical_port
                              or mac_address is already registered to a different device_id.
                              If False, conflicts are detected and logged as warnings.

        Returns:
            The authoritative registered Device record (defensive copy).

        Raises:
            DuplicateDeviceError: If a device with device.device_id already exists.
            DeviceConflictError: If reject_conflicts is True and a MAC/port conflict is detected.
        """
        if device.device_id in self._devices:
            raise DuplicateDeviceError(
                f"Device with ID '{device.device_id}' is already registered. "
                "Registration rejected; existing record was not overwritten."
            )

        conflicts = self.check_conflicts(device)
        if conflicts:
            conflict_msg = "; ".join(conflicts)
            if reject_conflicts:
                raise DeviceConflictError(
                    f"Registration rejected due to conflicts for device '{device.device_id}': {conflict_msg}"
                )
            logger.warning(
                "Conflict detected during registration of device '%s': %s",
                device.device_id,
                conflict_msg,
            )

        # Enforce registry status ownership:
        # All newly registered devices must start in QUARANTINED. An untrusted payload
        # cannot set itself to TRUSTED, ANOMALOUS, ISOLATED, or REJECTED.
        admitted_status = device.status
        if admitted_status != DeviceState.QUARANTINED:
            logger.warning(
                "Device '%s' attempted to register with status %s. "
                "Enforcing initial QUARANTINED state (trust lifecycle owned by engine).",
                device.device_id,
                admitted_status.value,
            )
            admitted_status = DeviceState.QUARANTINED

        # Defensive copy to isolate internal state from external object mutations
        stored_device = dataclass_replace(device, status=admitted_status)
        self._devices[device.device_id] = stored_device


        logger.info(
            "Registered device '%s' on port %s (status: %s)",
            stored_device.device_id,
            stored_device.physical_port,
            stored_device.status.value,
        )
        return dataclass_replace(stored_device)

    def get(self, device_id: str, default: Optional[Device] = None) -> Optional[Device]:
        """Look up a device by ID; returns default (None) if not found.

        Defined missing-ID behaviour: Safe non-raising query that returns None
        (or caller-specified default) when device_id is missing.

        Args:
            device_id: Identifier of the device to find.
            default: Value to return if device_id is not present.

        Returns:
            Defensive copy of Device if found, else default.
        """
        device = self._devices.get(device_id)
        if device is None:
            return default
        return dataclass_replace(device)

    def lookup(self, device_id: str) -> Device:
        """Look up a device by ID; raises DeviceNotFoundError if not found.

        Defined missing-ID behaviour: Strict query that raises DeviceNotFoundError
        (which also inherits from KeyError) when device_id is missing.

        Args:
            device_id: Identifier of the device to find.

        Returns:
            Defensive copy of the Device.

        Raises:
            DeviceNotFoundError: If device_id does not exist in the registry.
        """
        device = self._devices.get(device_id)
        if device is None:
            raise DeviceNotFoundError(
                f"Device with ID '{device_id}' was not found in the registry."
            )
        return dataclass_replace(device)

    def update_status(self, device_id: str, new_status: Union[DeviceState, str]) -> Device:
        """Authoritatively update the trust status of a registered device.

        This method is owned and called by the Trust Engine/Registry.

        Args:
            device_id: Identifier of the device to update.
            new_status: The new DeviceState or string equivalent.

        Returns:
            Defensive copy of the updated Device record.

        Raises:
            DeviceNotFoundError: If the device_id does not exist.
            ValueError: If new_status is not a valid DeviceState.
        """
        if device_id not in self._devices:
            raise DeviceNotFoundError(
                f"Cannot update status: device with ID '{device_id}' not found."
            )

        if isinstance(new_status, str):
            new_status = DeviceState.from_string(new_status)
        elif not isinstance(new_status, DeviceState):
            raise ValueError(
                f"new_status must be DeviceState or valid state string, got {type(new_status).__name__}."
            )

        current = self._devices[device_id]
        updated = dataclass_replace(current, status=new_status)
        self._devices[device_id] = updated

        logger.info(
            "Updated device '%s' status: %s -> %s",
            device_id,
            current.status.value,
            updated.status.value,
        )
        return dataclass_replace(updated)

    def check_conflicts(self, device: Device) -> List[str]:
        """Detect MAC or port conflicts with existing devices in the registry.

        Args:
            device: The device to check against registered records.

        Returns:
            List of human-readable conflict descriptions, empty if no conflicts.
        """
        conflicts: List[str] = []
        for existing_id, existing in self._devices.items():
            if existing_id == device.device_id:
                continue

            if str(existing.physical_port) == str(device.physical_port):
                conflicts.append(
                    f"Port conflict: physical port '{device.physical_port}' is already bound to device '{existing_id}'"
                )

            if existing.mac_address.strip().lower() == device.mac_address.strip().lower():
                conflicts.append(
                    f"MAC conflict: MAC address '{device.mac_address}' is already registered to device '{existing_id}'"
                )

        return conflicts

    def list_devices(self) -> List[Device]:
        """Return defensive copies of all registered devices."""
        return [dataclass_replace(d) for d in self._devices.values()]

    def clear(self) -> None:
        """Clear all records from the registry."""
        self._devices.clear()

    def __getitem__(self, device_id: str) -> Device:
        """Dictionary-style lookup by device_id. Raises DeviceNotFoundError if missing."""
        return self.lookup(device_id)

    def __contains__(self, device_id: str) -> bool:
        """Check whether a device_id is present in the registry."""
        return device_id in self._devices

    def __len__(self) -> int:
        """Return the number of registered devices."""
        return len(self._devices)

    def __iter__(self) -> Iterator[str]:
        """Iterate over registered device IDs."""
        return iter(self._devices.keys())
