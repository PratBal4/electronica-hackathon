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
from trust_engine.esp32_transport import (
    CURRENT_PROTOCOL_VERSION,
    DEFAULT_MAX_FRAME_BYTES,
    ESP32Frame,
    ESP32FrameParser,
    FrameErrorReason,
    FrameParseError,
    FrameParseResult,
    SyntheticESP32Source,
    compute_frame_crc32,
    format_esp32_frame,
)
from trust_engine.policy import (
    DecisionType,
    PolicyConfig,
    PolicyDecision,
    PolicyEngine,
)
from trust_engine.registry import (
    DeviceConflictError,
    DeviceNotFoundError,
    DeviceRegistry,
    DuplicateDeviceError,
    RegistryError,
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
    "CURRENT_PROTOCOL_VERSION",
    "DEFAULT_MAX_FRAME_BYTES",
    "DecisionType",
    "Device",
    "DeviceConflictError",
    "DeviceNotFoundError",
    "DeviceRegistry",
    "DeviceState",
    "DuplicateDeviceError",
    "ESP32Frame",
    "ESP32FrameParser",
    "EnforcementActionType",
    "EnforcementAdapter",
    "EnforcementResult",
    "FrameErrorReason",
    "FrameParseError",
    "FrameParseResult",
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
    "SyntheticESP32Source",
    "TelemetryValidationError",
    "TelemetryValidator",
    "TrustEngine",
    "ValidationResult",
    "compute_frame_crc32",
    "format_esp32_frame",
    "sanitize_audit_data",
    "validate_network_telemetry",
    "validate_physical_telemetry",
]


