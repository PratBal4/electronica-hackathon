"""Smart Backplane Trust Engine package.

Authoritative trust evaluation, lifecycle state management, and device registry
for Raspberry Pi 3B+ Smart Backplane dock monitor.
"""

from trust_engine.device import Device
from trust_engine.registry import (
    DeviceConflictError,
    DeviceNotFoundError,
    DeviceRegistry,
    DuplicateDeviceError,
    RegistryError,
)
from trust_engine.states import DeviceState

__all__ = [
    "Device",
    "DeviceConflictError",
    "DeviceNotFoundError",
    "DeviceRegistry",
    "DeviceState",
    "DuplicateDeviceError",
    "RegistryError",
]
