"""Device model for the Smart Backplane Trust Engine.

Defines the Device dataclass representing a docked peripheral connected to
a dock port. Per-instance state ensures no shared mutable state across devices.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Union

from trust_engine.states import DeviceState


@dataclass
class Device:
    """Represents a device connected to the Smart Backplane dock.

    Attributes:
        device_id: Authoritative internal unique identifier for the device record.
        mac_address: Observed MAC address of the device (evidence, not proof).
        physical_port: Dock port number or identifier where the device is physically connected.
        ip_address: Optional observed IP address of the device.
        status: Authoritative trust state. Owned strictly by the Trust Engine/Registry.
                Defaults to DeviceState.QUARANTINED.
    """

    device_id: str
    mac_address: str
    physical_port: Union[int, str]
    ip_address: Optional[str] = None
    status: DeviceState = field(default=DeviceState.QUARANTINED)

    def __post_init__(self) -> None:
        """Validate fields and normalize status to DeviceState."""
        if not isinstance(self.device_id, str) or not self.device_id.strip():
            raise ValueError("device_id must be a non-empty string.")

        if not isinstance(self.mac_address, str) or not self.mac_address.strip():
            raise ValueError("mac_address must be a non-empty string.")

        if isinstance(self.physical_port, str):
            if not self.physical_port.strip():
                raise ValueError("physical_port as string must not be empty.")
        elif not isinstance(self.physical_port, int):
            raise ValueError("physical_port must be an integer or non-empty string.")

        if self.ip_address is not None:
            if not isinstance(self.ip_address, str) or not self.ip_address.strip():
                raise ValueError("ip_address must be None or a non-empty string.")

        if isinstance(self.status, str):
            self.status = DeviceState.from_string(self.status)
        elif not isinstance(self.status, DeviceState):
            raise ValueError(
                f"status must be a DeviceState instance or valid state string, got {type(self.status).__name__}."
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert the device record to a dictionary representation."""
        return {
            "device_id": self.device_id,
            "mac_address": self.mac_address,
            "physical_port": self.physical_port,
            "ip_address": self.ip_address,
            "status": self.status.value,
        }
