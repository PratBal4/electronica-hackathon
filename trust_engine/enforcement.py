"""Enforcement interface and simulation adapter for the Smart Backplane Trust Engine.

Defines the narrow enforcement contract:
- isolate_device(device_id, reason)
- restore_quarantine(device_id, reason)
- set_port_power(physical_port, enabled, reason)

IMPORTANT SAFETY DISCLAIMER:
    The SimulatedEnforcementAdapter performs NO real system command execution,
    NO Linux firewall/iptables rules modification, and NO GPIO pin switching.
    All actions are safely recorded in-memory for validation and audit.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
import logging
import time
from typing import Any, Dict, List, Optional, Union

from trust_engine.audit import AuditEventType, AuditLog
from trust_engine.registry import DeviceRegistry

logger = logging.getLogger("trust_engine.enforcement")


class EnforcementActionType(str, Enum):
    """Types of enforcement actions."""

    ISOLATE_DEVICE = "ISOLATE_DEVICE"
    RESTORE_QUARANTINE = "RESTORE_QUARANTINE"
    SET_PORT_POWER = "SET_PORT_POWER"

    def __str__(self) -> str:
        return self.value


@dataclass
class EnforcementResult:
    """Outcome of an enforcement action request.

    Attributes:
        success: Whether the requested enforcement action was accepted and recorded.
        action: The EnforcementActionType requested.
        target: Target identifier (device_id or physical_port).
        reason: Documented reason for the enforcement request.
        timestamp: POSIX timestamp when action was processed.
        is_simulation: True, explicitly confirming no hardware was manipulated.
        error_message: Error explanation if success is False.
        details: Additional contextual data.
    """

    success: bool
    action: EnforcementActionType
    target: str
    reason: str
    timestamp: float
    is_simulation: bool = True
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "success": self.success,
            "action": self.action.value,
            "target": self.target,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "is_simulation": self.is_simulation,
            "error_message": self.error_message,
            "details": self.details,
        }


class EnforcementAdapter(ABC):
    """Abstract interface for Smart Backplane enforcement adapters."""

    @abstractmethod
    def isolate_device(self, device_id: str, reason: str) -> EnforcementResult:
        """Enforce network and policy isolation on a device."""

    @abstractmethod
    def restore_quarantine(self, device_id: str, reason: str) -> EnforcementResult:
        """Restore a device to quarantined state for re-validation."""

    @abstractmethod
    def set_port_power(
        self, physical_port: Union[int, str], enabled: bool, reason: str
    ) -> EnforcementResult:
        """Request enabling or disabling power on a physical dock port."""


class SimulatedEnforcementAdapter(EnforcementAdapter):
    """In-memory simulation adapter for testing and demonstrations.

    Guarantees:
    - Never executes shell commands, sub-processes, or raw socket calls.
    - Never manipulates Raspberry Pi GPIO pins or INA3221 bus registers.
    - Validates target IDs and arguments; fails safely on invalid inputs.
    - Records all requests into an inspectable in-memory action log.
    """

    def __init__(
        self,
        registry: Optional[DeviceRegistry] = None,
        audit_log: Optional[AuditLog] = None,
        simulate_failure: bool = False,
    ) -> None:
        """Initialize simulation adapter.

        Args:
            registry: Optional DeviceRegistry for checking valid device registration.
            audit_log: Optional AuditLog for recording enforcement events.
            simulate_failure: If True, adapter simulates communication/hardware failures.
        """
        self.registry = registry
        self.audit_log = audit_log
        self.simulate_failure = simulate_failure
        self.recorded_actions: List[EnforcementResult] = []

    def isolate_device(self, device_id: str, reason: str) -> EnforcementResult:
        """Simulate isolating a device from the network.

        Validates device_id and checks registry if available. Fails safely on unknown IDs.
        """
        now = time.time()
        action = EnforcementActionType.ISOLATE_DEVICE

        # 1. Input validation
        if not isinstance(device_id, str) or not device_id.strip():
            return self._fail(action, str(device_id), reason, now, "device_id must be a non-empty string.")

        if not isinstance(reason, str) or not reason.strip():
            return self._fail(action, device_id, reason, now, "reason must be an explicit non-empty string.")

        # 2. Unknown device safe failure check
        if self.registry is not None and device_id not in self.registry:
            return self._fail(
                action, device_id, reason, now, f"Unknown device ID '{device_id}'; not found in registry."
            )

        # 3. Simulated adapter failure
        if self.simulate_failure:
            return self._adapter_error(action, device_id, reason, now, "Simulated adapter communication failure.")

        # 4. Successful simulated action
        result = EnforcementResult(
            success=True,
            action=action,
            target=device_id,
            reason=reason,
            timestamp=now,
            is_simulation=True,
            details={"simulated_enforcement": "SIMULATED_NETWORK_ISOLATION_REQUESTED"},
        )
        self._record_success(result)
        return result

    def restore_quarantine(self, device_id: str, reason: str) -> EnforcementResult:
        """Simulate restoring a device to quarantined status."""
        now = time.time()
        action = EnforcementActionType.RESTORE_QUARANTINE

        if not isinstance(device_id, str) or not device_id.strip():
            return self._fail(action, str(device_id), reason, now, "device_id must be a non-empty string.")

        if not isinstance(reason, str) or not reason.strip():
            return self._fail(action, device_id, reason, now, "reason must be an explicit non-empty string.")

        if self.registry is not None and device_id not in self.registry:
            return self._fail(
                action, device_id, reason, now, f"Unknown device ID '{device_id}'; not found in registry."
            )

        if self.simulate_failure:
            return self._adapter_error(action, device_id, reason, now, "Simulated adapter communication failure.")

        result = EnforcementResult(
            success=True,
            action=action,
            target=device_id,
            reason=reason,
            timestamp=now,
            is_simulation=True,
            details={"simulated_enforcement": "SIMULATED_RESTORE_TO_QUARANTINE"},
        )
        self._record_success(result)
        return result

    def set_port_power(
        self, physical_port: Union[int, str], enabled: bool, reason: str
    ) -> EnforcementResult:
        """Simulate enabling or disabling power on a physical dock port."""
        now = time.time()
        action = EnforcementActionType.SET_PORT_POWER
        target_str = str(physical_port)

        # Port validation
        if isinstance(physical_port, bool):
            return self._fail(action, target_str, reason, now, "physical_port must be int or str, got bool.")

        if isinstance(physical_port, int) and physical_port <= 0:
            return self._fail(
                action, target_str, reason, now, f"Invalid port number '{physical_port}'; must be positive int."
            )

        if isinstance(physical_port, str) and not physical_port.strip():
            return self._fail(action, target_str, reason, now, "physical_port as string must not be empty.")

        if not isinstance(reason, str) or not reason.strip():
            return self._fail(action, target_str, reason, now, "reason must be an explicit non-empty string.")

        if self.simulate_failure:
            return self._adapter_error(action, target_str, reason, now, "Simulated power-switch adapter failure.")

        power_state = "POWER_ON" if enabled else "POWER_OFF"
        result = EnforcementResult(
            success=True,
            action=action,
            target=target_str,
            reason=reason,
            timestamp=now,
            is_simulation=True,
            details={"requested_power": power_state, "simulated": True},
        )
        self._record_success(result)
        return result

    def _fail(
        self,
        action: EnforcementActionType,
        target: str,
        reason: str,
        timestamp: float,
        error_message: str,
    ) -> EnforcementResult:
        """Record and return a safe validation failure result."""
        result = EnforcementResult(
            success=False,
            action=action,
            target=target,
            reason=reason,
            timestamp=timestamp,
            is_simulation=True,
            error_message=error_message,
        )
        self.recorded_actions.append(result)
        if self.audit_log is not None:
            self.audit_log.record(
                event_type=AuditEventType.ENFORCEMENT_REQUEST,
                reason_code="ENFORCEMENT_VALIDATION_FAILED",
                device_id=target if action != EnforcementActionType.SET_PORT_POWER else None,
                details=result.to_dict(),
                severity="WARNING",
            )
        logger.warning(
            "Enforcement request %s on '%s' failed safely: %s",
            action.value,
            target,
            error_message,
        )
        return result

    def _adapter_error(
        self,
        action: EnforcementActionType,
        target: str,
        reason: str,
        timestamp: float,
        error_message: str,
    ) -> EnforcementResult:
        """Record and return a simulated adapter communication error."""
        result = EnforcementResult(
            success=False,
            action=action,
            target=target,
            reason=reason,
            timestamp=timestamp,
            is_simulation=True,
            error_message=error_message,
        )
        self.recorded_actions.append(result)
        if self.audit_log is not None:
            self.audit_log.record(
                event_type=AuditEventType.ADAPTER_FAILURE,
                reason_code="ADAPTER_COMMUNICATION_ERROR",
                device_id=target if action != EnforcementActionType.SET_PORT_POWER else None,
                details=result.to_dict(),
                severity="ERROR",
            )
        logger.error(
            "Enforcement adapter simulated failure during %s on '%s': %s",
            action.value,
            target,
            error_message,
        )
        return result

    def _record_success(self, result: EnforcementResult) -> None:
        """Store result and notify audit log."""
        self.recorded_actions.append(result)
        if self.audit_log is not None:
            self.audit_log.record(
                event_type=AuditEventType.ENFORCEMENT_RESULT,
                reason_code=f"{result.action.value}_SIMULATED",
                device_id=result.target if result.action != EnforcementActionType.SET_PORT_POWER else None,
                details=result.to_dict(),
                severity="INFO",
            )
        logger.info(
            "Simulated enforcement %s executed on '%s' (Reason: %s)",
            result.action.value,
            result.target,
            result.reason,
        )

    def clear(self) -> None:
        """Clear recorded actions log."""
        self.recorded_actions.clear()
