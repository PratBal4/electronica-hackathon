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
from trust_engine.engine import (
    ALLOWED_TRANSITIONS,
    IllegalStateTransitionError,
    TrustEngine,
)
from trust_engine.policy import (
    DecisionType,
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
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
    "ALLOWED_TRANSITIONS",
    "DecisionType",
    "Device",
    "DeviceConflictError",
    "DeviceNotFoundError",
    "DeviceRegistry",
    "DeviceState",
    "DuplicateDeviceError",
    "IllegalStateTransitionError",
    "NetworkBoundsConfig",
    "NetworkTelemetry",
    "PhysicalBoundsConfig",
    "PhysicalTelemetry",
    "PolicyConfig",
    "PolicyDecision",
    "PolicyEngine",
    "RegistryError",
    "TelemetryValidationError",
    "TelemetryValidator",
    "TrustEngine",
    "ValidationResult",
    "validate_network_telemetry",
    "validate_physical_telemetry",
]

