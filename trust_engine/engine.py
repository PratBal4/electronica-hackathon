"""Trust Engine orchestration for the Smart Backplane.

Central authority for device registration, state machine transitions, telemetry
filtering, and deterministic policy execution. Enforces centralized state
transitions where every decision and transition records an explicit reason.
"""

from copy import deepcopy
import logging
import time
from typing import Any, Dict, List, Optional, Set

from trust_engine.device import Device
from trust_engine.policy import DecisionType, PolicyConfig, PolicyDecision, PolicyEngine
from trust_engine.registry import DeviceNotFoundError, DeviceRegistry
from trust_engine.states import DeviceState
from trust_engine.telemetry import (
    NetworkTelemetry,
    PhysicalTelemetry,
    TelemetryValidator,
    validate_network_telemetry,
    validate_physical_telemetry,
)

logger = logging.getLogger(__name__)


class IllegalStateTransitionError(ValueError):
    """Raised when an unauthorized or invalid state transition is attempted."""


# Centralized, strictly validated state transition graph
ALLOWED_TRANSITIONS: Dict[DeviceState, Set[DeviceState]] = {
    DeviceState.UNKNOWN: {DeviceState.QUARANTINED},
    DeviceState.QUARANTINED: {DeviceState.TRUSTED, DeviceState.REJECTED},
    DeviceState.TRUSTED: {DeviceState.ANOMALOUS, DeviceState.ISOLATED},
    DeviceState.ANOMALOUS: {DeviceState.ISOLATED, DeviceState.TRUSTED},
    DeviceState.ISOLATED: {DeviceState.QUARANTINED},
    DeviceState.REJECTED: set(),  # Terminal state
}


class TrustEngine:
    """Orchestrates device admission, monitoring, and authoritative state transitions.

    Guarantees:
    - Only the Trust Engine can transition a device to TRUSTED.
    - Transitions are centralized and validated against ALLOWED_TRANSITIONS.
    - Every transition requires an explicit reason.
    - Invalid telemetry is rejected and never treated as trusted evidence.
    - Identity confidence is kept separate from behavioral assessment.
    """

    def __init__(
        self,
        registry: Optional[DeviceRegistry] = None,
        policy_engine: Optional[PolicyEngine] = None,
        telemetry_validator: Optional[TelemetryValidator] = None,
    ) -> None:
        """Initialize TrustEngine with registry, policy engine, and validator."""
        self.registry = registry or DeviceRegistry()
        self.policy_engine = policy_engine or PolicyEngine()
        self.telemetry_validator = telemetry_validator or TelemetryValidator()

        self._admission_start_times: Dict[str, float] = {}
        self._anomaly_counts: Dict[str, int] = {}
        self._transition_history: List[Dict[str, Any]] = []

    def register_device(self, device: Device, reject_conflicts: bool = False) -> Device:
        """Register a new device into the registry and track admission start.

        All devices enter in QUARANTINED state.
        """
        registered = self.registry.register(device, reject_conflicts=reject_conflicts)
        now = time.time()
        self._admission_start_times[registered.device_id] = now
        self._anomaly_counts[registered.device_id] = 0

        self._record_transition(
            device_id=registered.device_id,
            from_state=None,
            to_state=registered.status,
            reason="Initial registration into quarantine",
            timestamp=now,
        )
        return registered

    def validate_transition(self, current_state: DeviceState, target_state: DeviceState) -> bool:
        """Check whether a transition between two states is permitted."""
        allowed = ALLOWED_TRANSITIONS.get(current_state, set())
        return target_state in allowed

    def transition_device(
        self,
        device_id: str,
        target_state: DeviceState,
        reason: str,
    ) -> Device:
        """Authoritatively transition a device to target_state with validation and audit.

        Args:
            device_id: Identifier of the device.
            target_state: Desired lifecycle state.
            reason: Explicit reason for the state transition.

        Returns:
            Updated Device record.

        Raises:
            DeviceNotFoundError: If device is not registered.
            IllegalStateTransitionError: If the transition violates the transition graph.
            ValueError: If reason is empty or target_state is invalid.
        """
        if not reason or not reason.strip():
            raise ValueError("Every state transition must have an explicit non-empty reason.")

        device = self.registry.lookup(device_id)
        current_state = device.status

        # If already in the target state, no-op
        if current_state == target_state:
            return device

        if not self.validate_transition(current_state, target_state):
            allowed_names = [s.name for s in ALLOWED_TRANSITIONS.get(current_state, set())]
            error_msg = (
                f"Illegal state transition for device '{device_id}' from {current_state.name} "
                f"to {target_state.name}. Allowed transitions from {current_state.name} are: {allowed_names}. "
                f"Attempted reason: '{reason}'."
            )
            logger.error(error_msg)
            raise IllegalStateTransitionError(error_msg)

        # Update registry state authoritatively
        updated = self.registry.update_status(device_id, target_state)
        now = time.time()
        self._record_transition(
            device_id=device_id,
            from_state=current_state,
            to_state=target_state,
            reason=reason,
            timestamp=now,
        )
        logger.info(
            "Device '%s' transitioned %s -> %s (Reason: %s)",
            device_id,
            current_state.name,
            target_state.name,
            reason,
        )
        return updated

    def evaluate_admission(
        self,
        device_id: str,
        physical_telemetry: Optional[List[PhysicalTelemetry]] = None,
        network_telemetry: Optional[List[NetworkTelemetry]] = None,
        current_time: Optional[float] = None,
    ) -> PolicyDecision:
        """Evaluate admission policy for a device and enact state change if approved/rejected.

        Args:
            device_id: Identifier of device in quarantine.
            physical_telemetry: Physical telemetry readings.
            network_telemetry: Network telemetry readings.
            current_time: Reference time for evaluating freshness and timeout.

        Returns:
            PolicyDecision with verdict and evidence summary.
        """
        device = self.registry.lookup(device_id)
        if device.status not in (DeviceState.QUARANTINED, DeviceState.UNKNOWN):
            raise ValueError(
                f"Cannot evaluate admission for device '{device_id}' in state {device.status.value}; "
                "device must be in QUARANTINED."
            )
        ref_time = current_time if current_time is not None else time.time()


        # Filter and validate physical telemetry: invalid data must NOT become evidence
        valid_physical: List[PhysicalTelemetry] = []
        if physical_telemetry:
            for p in physical_telemetry:
                v_res = self.telemetry_validator.validate_physical(p, current_time=ref_time)
                if v_res.is_valid:
                    valid_physical.append(p)
                else:
                    logger.warning(
                        "Discarded invalid physical telemetry during admission for '%s': %s",
                        device_id,
                        "; ".join(v_res.errors),
                    )

        # Filter and validate network telemetry
        valid_network: List[NetworkTelemetry] = []
        if network_telemetry:
            for n in network_telemetry:
                n_res = self.telemetry_validator.validate_network(n, current_time=ref_time)
                if n_res.is_valid:
                    valid_network.append(n)
                else:
                    logger.warning(
                        "Discarded invalid network telemetry during admission for '%s': %s",
                        device_id,
                        "; ".join(n_res.errors),
                    )

        # Check for MAC/port conflicts
        conflicts = self.registry.check_conflicts(device)
        has_conflict = len(conflicts) > 0

        # Calculate elapsed admission time
        start_time = self._admission_start_times.get(device_id, ref_time)
        elapsed = max(0.0, ref_time - start_time)

        # Evaluate policy
        decision = self.policy_engine.evaluate_admission(
            device=device,
            physical_telemetry=valid_physical,
            network_telemetry=valid_network,
            has_identity_conflict=has_conflict,
            conflict_reasons=conflicts,
            elapsed_admission_time=elapsed,
        )

        # Enact authoritative state transition if recommended
        if decision.decision_type == DecisionType.ALLOW:
            self.transition_device(
                device_id=device_id,
                target_state=DeviceState.TRUSTED,
                reason=f"Admission approved: {decision.explanation}",
            )
        elif decision.decision_type == DecisionType.REJECT:
            self.transition_device(
                device_id=device_id,
                target_state=DeviceState.REJECTED,
                reason=f"Admission rejected: {decision.explanation}",
            )

        return decision

    def evaluate_monitoring(
        self,
        device_id: str,
        physical_telemetry: Optional[List[PhysicalTelemetry]] = None,
        network_telemetry: Optional[List[NetworkTelemetry]] = None,
        current_time: Optional[float] = None,
    ) -> PolicyDecision:
        """Evaluate behavioral monitoring for an admitted device and enact restrictions if needed.

        Args:
            device_id: Identifier of active device.
            physical_telemetry: Observed physical telemetry readings.
            network_telemetry: Observed network telemetry readings.
            current_time: Reference time for validation.

        Returns:
            PolicyDecision with verdict.
        """
        device = self.registry.lookup(device_id)
        if device.status not in (DeviceState.TRUSTED, DeviceState.ANOMALOUS):
            raise ValueError(
                f"Cannot evaluate monitoring for device '{device_id}' in state {device.status.value}; "
                "device must be active in TRUSTED or ANOMALOUS."
            )
        ref_time = current_time if current_time is not None else time.time()


        # Validate incoming telemetry
        valid_physical: List[PhysicalTelemetry] = []
        if physical_telemetry:
            for p in physical_telemetry:
                if self.telemetry_validator.validate_physical(p, current_time=ref_time).is_valid:
                    valid_physical.append(p)

        valid_network: List[NetworkTelemetry] = []
        if network_telemetry:
            for n in network_telemetry:
                if self.telemetry_validator.validate_network(n, current_time=ref_time).is_valid:
                    valid_network.append(n)

        prior_anomalies = self._anomaly_counts.get(device_id, 0)
        decision = self.policy_engine.evaluate_monitoring(
            device=device,
            physical_telemetry=valid_physical,
            network_telemetry=valid_network,
            prior_anomaly_count=prior_anomalies,
        )

        if decision.decision_type == DecisionType.ISOLATE:
            self.transition_device(
                device_id=device_id,
                target_state=DeviceState.ISOLATED,
                reason=f"Isolation triggered: {decision.explanation}",
            )
        elif decision.decision_type == DecisionType.ANOMALOUS:
            self._anomaly_counts[device_id] = prior_anomalies + 1
            if device.status != DeviceState.ANOMALOUS:
                self.transition_device(
                    device_id=device_id,
                    target_state=DeviceState.ANOMALOUS,
                    reason=f"Anomalous behavior: {decision.explanation}",
                )

        return decision

    def get_anomaly_count(self, device_id: str) -> int:
        """Return the number of anomalies recorded for a device."""
        return self._anomaly_counts.get(device_id, 0)

    def get_transition_history(self, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return audit history of state transitions."""
        if device_id is None:
            return deepcopy(self._transition_history)
        return [deepcopy(entry) for entry in self._transition_history if entry["device_id"] == device_id]

    def _record_transition(
        self,
        device_id: str,
        from_state: Optional[DeviceState],
        to_state: DeviceState,
        reason: str,
        timestamp: float,
    ) -> None:
        """Internal audit recorder for state transitions."""
        self._transition_history.append(
            {
                "device_id": device_id,
                "from_state": from_state.value if from_state else None,
                "to_state": to_state.value,
                "reason": reason,
                "timestamp": timestamp,
            }
        )
