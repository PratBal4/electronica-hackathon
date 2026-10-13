"""Deterministic policy evaluation for the Smart Backplane Trust Engine.

Evaluates device records and validated physical/network telemetry using
explicit, explainable rules. Zero machine learning, zero opaque scores.
Every decision includes reason codes, human-readable explanations, and
an evidence summary.
"""

from dataclasses import dataclass, field
from enum import Enum
import logging
from typing import Any, Dict, List, Optional, Sequence

from trust_engine.device import Device
from trust_engine.states import DeviceState
from trust_engine.telemetry import NetworkTelemetry, PhysicalTelemetry

logger = logging.getLogger(__name__)


class DecisionType(str, Enum):
    """Classification of policy decision outcome."""

    ALLOW = "ALLOW"
    KEEP_QUARANTINED = "KEEP_QUARANTINED"
    ANOMALOUS = "ANOMALOUS"
    ISOLATE = "ISOLATE"
    REJECT = "REJECT"

    def __str__(self) -> str:
        return self.value


@dataclass
class PolicyDecision:
    """Structured result of policy evaluation.

    Attributes:
        decision_type: Type of action/verdict recommended.
        recommended_state: Recommended DeviceState lifecycle transition.
        reason_codes: Programmatic identifiers for the rationale.
        explanation: Human-readable narrative of the decision.
        evidence_summary: Key telemetry readings and facts used in evaluation.
    """

    decision_type: DecisionType
    recommended_state: DeviceState
    reason_codes: List[str]
    explanation: str
    evidence_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert policy decision to dictionary representation."""
        return {
            "decision_type": self.decision_type.value,
            "recommended_state": self.recommended_state.value,
            "reason_codes": self.reason_codes,
            "explanation": self.explanation,
            "evidence_summary": self.evidence_summary,
        }


@dataclass(frozen=True)
class PolicyConfig:
    """Configurable thresholds for admission and behavioural monitoring."""

    # Admission timing
    admission_timeout_seconds: float = 30.0

    # Minimum evidence counts required for admission
    min_physical_readings: int = 1
    min_network_readings: int = 1

    # Nominal physical baseline for dock admission (e.g. 5V rail ± 5%, idle current)
    nominal_voltage_min: float = 4.75
    nominal_voltage_max: float = 5.25
    nominal_current_min: float = 0.01
    nominal_current_max: float = 2.50

    # Behavioral monitoring thresholds
    max_mild_anomalies: int = 2
    severe_byte_threshold: int = 10_000_000  # 10MB unexpected burst
    severe_packet_threshold: int = 50_000

    # Prohibited destinations, protocols, and ports
    prohibited_destinations: Sequence[str] = (
        "botnet.c2",
        "malicious.local",
        "0.0.0.0",
        "attacker.sinkhole",
    )
    prohibited_protocols: Sequence[str] = ("TELNET", "BITTORRENT")
    prohibited_ports: Sequence[int] = (6667, 1337, 4444)


class PolicyEngine:
    """Deterministic policy evaluator for device admission and monitoring.

    Rules are explicit and explainable:
    1. Identity/port conflicts block automatic admission.
    2. Insufficient evidence keeps device in QUARANTINED.
    3. Admission timeout ends attempt without attributing malice.
    4. Compliance with nominal physical bounds & network rules permits admission.
    5. One mild anomaly triggers observation (ANOMALOUS), not immediate isolation.
    6. Severe violations or repeated anomalies (> max_mild_anomalies) trigger ISOLATE.
    """

    def __init__(self, config: Optional[PolicyConfig] = None) -> None:
        """Initialize PolicyEngine with configurable policy rules."""
        self.config = config or PolicyConfig()

    def evaluate_admission(
        self,
        device: Device,
        physical_telemetry: Optional[List[PhysicalTelemetry]] = None,
        network_telemetry: Optional[List[NetworkTelemetry]] = None,
        has_identity_conflict: bool = False,
        conflict_reasons: Optional[List[str]] = None,
        elapsed_admission_time: float = 0.0,
    ) -> PolicyDecision:
        """Evaluate admission criteria for a quarantined device.

        Args:
            device: Registered device record.
            physical_telemetry: Validated physical telemetry readings.
            network_telemetry: Validated network telemetry readings.
            has_identity_conflict: Whether MAC or physical port conflicts exist.
            conflict_reasons: Descriptions of any detected conflicts.
            elapsed_admission_time: Seconds elapsed since device registered.

        Returns:
            Structured PolicyDecision.
        """
        phys_list = physical_telemetry or []
        net_list = network_telemetry or []

        evidence: Dict[str, Any] = {
            "device_id": device.device_id,
            "physical_port": device.physical_port,
            "mac_address": device.mac_address,
            "current_status": device.status.value,
            "physical_readings_count": len(phys_list),
            "network_readings_count": len(net_list),
            "elapsed_seconds": elapsed_admission_time,
        }

        # Rule 1: Identity or Port Conflicts Prevent Admission
        if has_identity_conflict:
            conflicts_desc = "; ".join(conflict_reasons or ["Unspecified conflict"])
            evidence["conflict_details"] = conflicts_desc
            logger.warning(
                "Admission rejected for device '%s': Identity/Port conflict (%s)",
                device.device_id,
                conflicts_desc,
            )
            return PolicyDecision(
                decision_type=DecisionType.REJECT,
                recommended_state=DeviceState.REJECTED,
                reason_codes=["IDENTITY_CONFLICT"],
                explanation=f"Admission rejected: device conflicts with existing dock bindings ({conflicts_desc}).",
                evidence_summary=evidence,
            )

        # Rule 2: Admission Timeout
        if elapsed_admission_time >= self.config.admission_timeout_seconds:
            logger.info(
                "Admission timed out for device '%s' after %.1fs",
                device.device_id,
                elapsed_admission_time,
            )
            return PolicyDecision(
                decision_type=DecisionType.REJECT,
                recommended_state=DeviceState.REJECTED,
                reason_codes=["ADMISSION_TIMEOUT"],
                explanation=(
                    f"Admission period expired after {elapsed_admission_time:.1f}s without required "
                    "evidence. Timeout does not prove malice; re-admission requires re-docking."
                ),
                evidence_summary=evidence,
            )

        # Rule 3: Minimum Evidence Requirement
        if (
            len(phys_list) < self.config.min_physical_readings
            or len(net_list) < self.config.min_network_readings
        ):
            missing: List[str] = []
            if len(phys_list) < self.config.min_physical_readings:
                missing.append(
                    f"physical readings (received {len(phys_list)}/{self.config.min_physical_readings})"
                )
            if len(net_list) < self.config.min_network_readings:
                missing.append(
                    f"network readings (received {len(net_list)}/{self.config.min_network_readings})"
                )
            missing_msg = ", ".join(missing)

            return PolicyDecision(
                decision_type=DecisionType.KEEP_QUARANTINED,
                recommended_state=DeviceState.QUARANTINED,
                reason_codes=["INSUFFICIENT_EVIDENCE"],
                explanation=f"Awaiting required admission evidence: missing {missing_msg}.",
                evidence_summary=evidence,
            )

        # Rule 4: Physical Baseline Validation
        for p in phys_list:
            if not (self.config.nominal_voltage_min <= p.voltage_v <= self.config.nominal_voltage_max):
                evidence["failing_voltage"] = p.voltage_v
                return PolicyDecision(
                    decision_type=DecisionType.REJECT,
                    recommended_state=DeviceState.REJECTED,
                    reason_codes=["PHYSICAL_BASELINE_OUT_OF_SPEC"],
                    explanation=(
                        f"Voltage reading {p.voltage_v}V outside nominal dock baseline "
                        f"[{self.config.nominal_voltage_min}V, {self.config.nominal_voltage_max}V]."
                    ),
                    evidence_summary=evidence,
                )
            if not (self.config.nominal_current_min <= p.current_a <= self.config.nominal_current_max):
                evidence["failing_current"] = p.current_a
                return PolicyDecision(
                    decision_type=DecisionType.REJECT,
                    recommended_state=DeviceState.REJECTED,
                    reason_codes=["PHYSICAL_BASELINE_OUT_OF_SPEC"],
                    explanation=(
                        f"Current reading {p.current_a}A outside nominal dock baseline "
                        f"[{self.config.nominal_current_min}A, {self.config.nominal_current_max}A]."
                    ),
                    evidence_summary=evidence,
                )

        # Rule 5: Network Admission Rules
        for n in net_list:
            if n.destination in self.config.prohibited_destinations:
                evidence["prohibited_destination"] = n.destination
                return PolicyDecision(
                    decision_type=DecisionType.REJECT,
                    recommended_state=DeviceState.REJECTED,
                    reason_codes=["PROHIBITED_DESTINATION"],
                    explanation=f"Traffic directed to prohibited destination: {n.destination}.",
                    evidence_summary=evidence,
                )

            if n.protocol.upper() in self.config.prohibited_protocols:
                evidence["prohibited_protocol"] = n.protocol
                return PolicyDecision(
                    decision_type=DecisionType.REJECT,
                    recommended_state=DeviceState.REJECTED,
                    reason_codes=["PROHIBITED_PROTOCOL"],
                    explanation=f"Traffic uses prohibited protocol: {n.protocol}.",
                    evidence_summary=evidence,
                )

            if (
                n.destination_port in self.config.prohibited_ports
                or n.source_port in self.config.prohibited_ports
            ):
                port = n.destination_port if n.destination_port in self.config.prohibited_ports else n.source_port
                evidence["prohibited_port"] = port
                return PolicyDecision(
                    decision_type=DecisionType.REJECT,
                    recommended_state=DeviceState.REJECTED,
                    reason_codes=["PROHIBITED_PORT"],
                    explanation=f"Traffic associated with prohibited port: {port}.",
                    evidence_summary=evidence,
                )

        # Rule 6: Admission Approved
        evidence["admission_criteria_passed"] = True
        return PolicyDecision(
            decision_type=DecisionType.ALLOW,
            recommended_state=DeviceState.TRUSTED,
            reason_codes=["ADMISSION_PASSED"],
            explanation="Device satisfied all deterministic physical and network admission criteria.",
            evidence_summary=evidence,
        )

    def evaluate_monitoring(
        self,
        device: Device,
        physical_telemetry: Optional[List[PhysicalTelemetry]] = None,
        network_telemetry: Optional[List[NetworkTelemetry]] = None,
        prior_anomaly_count: int = 0,
    ) -> PolicyDecision:
        """Evaluate behavioral monitoring for an admitted device.

        Rules:
        - Severe violations (prohibited destinations, severe volume surges) immediately trigger ISOLATE.
        - Repeated mild anomalies (> max_mild_anomalies) trigger ISOLATE.
        - A single mild anomaly transitions to ANOMALOUS for continued observation (never immediate rejection).
        - Normal operation maintains TRUSTED.
        """
        phys_list = physical_telemetry or []
        net_list = network_telemetry or []

        evidence: Dict[str, Any] = {
            "device_id": device.device_id,
            "current_status": device.status.value,
            "prior_anomaly_count": prior_anomaly_count,
            "physical_samples": len(phys_list),
            "network_samples": len(net_list),
        }

        # 1. Check for Severe Network Policy Violations
        for n in net_list:
            if n.destination in self.config.prohibited_destinations:
                evidence["violation"] = f"communicated with prohibited destination {n.destination}"
                return PolicyDecision(
                    decision_type=DecisionType.ISOLATE,
                    recommended_state=DeviceState.ISOLATED,
                    reason_codes=["SEVERE_VIOLATION_PROHIBITED_DESTINATION"],
                    explanation=f"Severe violation: traffic directed to prohibited destination {n.destination}.",
                    evidence_summary=evidence,
                )

            if n.byte_count >= self.config.severe_byte_threshold:
                evidence["byte_count"] = n.byte_count
                return PolicyDecision(
                    decision_type=DecisionType.ISOLATE,
                    recommended_state=DeviceState.ISOLATED,
                    reason_codes=["SEVERE_VIOLATION_MASSIVE_BURST"],
                    explanation=(
                        f"Severe violation: traffic burst of {n.byte_count} bytes exceeds "
                        f"threshold of {self.config.severe_byte_threshold} bytes."
                    ),
                    evidence_summary=evidence,
                )

            if n.packet_count >= self.config.severe_packet_threshold:
                evidence["packet_count"] = n.packet_count
                return PolicyDecision(
                    decision_type=DecisionType.ISOLATE,
                    recommended_state=DeviceState.ISOLATED,
                    reason_codes=["SEVERE_VIOLATION_FLOOD"],
                    explanation=(
                        f"Severe violation: packet count of {n.packet_count} exceeds "
                        f"threshold of {self.config.severe_packet_threshold}."
                    ),
                    evidence_summary=evidence,
                )

        # 2. Check for Mild Anomalies
        mild_anomaly_detected = False
        mild_reason = ""

        for p in phys_list:
            # Current slightly higher than nominal, but within absolute safety limit
            if p.current_a > self.config.nominal_current_max:
                mild_anomaly_detected = True
                mild_reason = f"Mild current elevation: {p.current_a}A (nominal max: {self.config.nominal_current_max}A)"
                evidence["mild_anomaly_detail"] = mild_reason
                break

        if not mild_anomaly_detected:
            for n in net_list:
                # Moderate packet increase (e.g. 5,000 packets)
                if n.packet_count > 1000 and n.packet_count < self.config.severe_packet_threshold:
                    mild_anomaly_detected = True
                    mild_reason = f"Unusual packet burst: {n.packet_count} packets in observation window"
                    evidence["mild_anomaly_detail"] = mild_reason
                    break

        if mild_anomaly_detected:
            new_anomaly_count = prior_anomaly_count + 1
            evidence["new_anomaly_count"] = new_anomaly_count

            # Repeated anomalies rule: if occurrences exceed max_mild_anomalies, isolate
            if new_anomaly_count > self.config.max_mild_anomalies:
                return PolicyDecision(
                    decision_type=DecisionType.ISOLATE,
                    recommended_state=DeviceState.ISOLATED,
                    reason_codes=["REPEATED_ANOMALIES_EXCEEDED"],
                    explanation=(
                        f"Repeated anomalies exceeded threshold: {new_anomaly_count} occurrences "
                        f"(max allowed: {self.config.max_mild_anomalies}). Isolation recommended."
                    ),
                    evidence_summary=evidence,
                )

            # Single or mild anomaly: flag as ANOMALOUS for observation, NOT immediate isolation/rejection
            return PolicyDecision(
                decision_type=DecisionType.ANOMALOUS,
                recommended_state=DeviceState.ANOMALOUS,
                reason_codes=["MILD_ANOMALY"],
                explanation=f"{mild_reason}. Observation recommended; not rejected automatically.",
                evidence_summary=evidence,
            )

        # 3. All monitoring checks normal
        return PolicyDecision(
            decision_type=DecisionType.ALLOW,
            recommended_state=DeviceState.TRUSTED,
            reason_codes=["BEHAVIOR_NORMAL"],
            explanation="Device physical and network telemetry conform to normal operational parameters.",
            evidence_summary=evidence,
        )
