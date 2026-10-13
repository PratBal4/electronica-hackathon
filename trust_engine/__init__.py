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
from trust_engine.telemetry import (
    NetworkBoundsConfig,
    NetworkTelemetry,
    PhysicalBoundsConfig,
    PhysicalTelemetry,
    TelemetryValidationError,
    TelemetryValidator,
    ValidationResult,
    validate_network_telemetry,
    validate_physical_telemetry,
)

__all__ = [
    "Device",
    "DeviceConflictError",
    "DeviceNotFoundError",
    "DeviceRegistry",
    "DeviceState",
    "DuplicateDeviceError",
    "NetworkBoundsConfig",
    "NetworkTelemetry",
    "PhysicalBoundsConfig",
    "PhysicalTelemetry",
    "RegistryError",
    "TelemetryValidationError",
    "TelemetryValidator",
    "ValidationResult",
    "validate_network_telemetry",
    "validate_physical_telemetry",
]
