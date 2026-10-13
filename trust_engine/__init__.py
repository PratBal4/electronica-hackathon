"""Smart Backplane Trust Engine package.

Authoritative trust evaluation, lifecycle state management, and device registry
for Raspberry Pi 3B+ Smart Backplane dock monitor.
"""

from trust_engine.audit import (
    AuditEvent,
    AuditEventType,
    AuditLog,
    sanitize_audit_data,
)
from trust_engine.device import Device
from trust_engine.enforcement import (
    EnforcementActionType,
    EnforcementAdapter,
    EnforcementResult,
    SimulatedEnforcementAdapter,
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
from trust_engine.simulator import ScenarioResult, Simulator
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
    "AuditEvent",
    "AuditEventType",
    "AuditLog",
    "DecisionType",
    "Device",
    "DeviceConflictError",
    "DeviceNotFoundError",
    "DeviceRegistry",
    "DeviceState",
    "DuplicateDeviceError",
    "EnforcementActionType",
    "EnforcementAdapter",
    "EnforcementResult",
    "IllegalStateTransitionError",
    "NetworkBoundsConfig",
    "NetworkTelemetry",
    "PhysicalBoundsConfig",
    "PhysicalTelemetry",
    "PolicyConfig",
    "PolicyDecision",
    "PolicyEngine",
    "RegistryError",
    "ScenarioResult",
    "SimulatedEnforcementAdapter",
    "Simulator",
    "TelemetryValidationError",
    "TelemetryValidator",
    "TrustEngine",
    "ValidationResult",
    "sanitize_audit_data",
    "validate_network_telemetry",
    "validate_physical_telemetry",
]


