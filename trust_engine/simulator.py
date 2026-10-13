"""Deterministic scenario simulator for the Smart Backplane Trust Engine.

Demonstrates end-to-end device lifecycles:
1. Normal Admission: Quarantine -> Compliant Telemetry -> TRUSTED.
2. Insufficient Evidence: Quarantine -> Missing Network Telemetry -> Kept QUARANTINED.
3. Policy Violation & Isolation: Quarantine -> TRUSTED -> C2 Traffic Spike -> ISOLATED -> Simulated Enforcement.

SAFETY NOTICE:
    All enforcement actions are purely simulated in-memory. No firewall rules,
    network routes, or GPIO pins are modified.
"""

from dataclasses import dataclass
import time
from typing import Any, Dict, List, Optional

from trust_engine.audit import AuditEventType, AuditLog
from trust_engine.device import Device
from trust_engine.engine import TrustEngine
from trust_engine.enforcement import EnforcementResult, SimulatedEnforcementAdapter
from trust_engine.policy import DecisionType, PolicyDecision
from trust_engine.states import DeviceState
from trust_engine.telemetry import NetworkTelemetry, PhysicalTelemetry


@dataclass
class ScenarioResult:
    """Outcome report for an executed simulation scenario."""

    scenario_name: str
    device_id: str
    initial_state: DeviceState
    final_state: DeviceState
    decision: PolicyDecision
    enforcement_result: Optional[EnforcementResult] = None
    audit_event_count: int = 0
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert scenario result to dictionary."""
        return {
            "scenario_name": self.scenario_name,
            "device_id": self.device_id,
            "initial_state": self.initial_state.value,
            "final_state": self.final_state.value,
            "decision": self.decision.to_dict(),
            "enforcement_result": self.enforcement_result.to_dict() if self.enforcement_result else None,
            "audit_event_count": self.audit_event_count,
            "summary": self.summary,
        }


class Simulator:
    """Orchestrates deterministic demonstration scenarios."""

    def __init__(self) -> None:
        """Initialize simulation environment with engine, audit log, and simulated adapter."""
        self.audit_log = AuditLog()
        self.engine = TrustEngine()
        self.adapter = SimulatedEnforcementAdapter(
            registry=self.engine.registry,
            audit_log=self.audit_log,
        )

    def run_scenario_normal_admission(self) -> ScenarioResult:
        """Scenario 1: Normal Admission Flow.

        Device connects -> Quarantined -> Compliant Telemetry -> Admitted to TRUSTED.
        """
        device_id = "dock-dev-normal"
        dev = Device(device_id=device_id, mac_address="00:11:22:33:44:01", physical_port=1)

        # 1. Register device into quarantine
        self.engine.register_device(dev)
        initial_state = self.engine.registry.get(device_id).status

        self.audit_log.record(
            event_type=AuditEventType.DISCOVERY,
            reason_code="DEVICE_DOCKED",
            device_id=device_id,
            details={"physical_port": 1, "mac_address": "00:11:22:33:44:01"},
        )

        # 2. Supply compliant physical and network evidence
        now = time.time()
        phys = [PhysicalTelemetry(device_id, 1, voltage_v=5.02, current_a=0.45, timestamp=now)]
        net = [
            NetworkTelemetry(
                source_mac="00:11:22:33:44:01",
                source_ip="192.168.1.15",
                destination="192.168.1.1",
                protocol="TCP",
                packet_count=45,
                byte_count=3800,
                timestamp=now,
                destination_port=443,
            )
        ]

        # 3. Evaluate admission
        decision = self.engine.evaluate_admission(device_id, phys, net, current_time=now)
        final_state = self.engine.registry.get(device_id).status

        self.audit_log.record(
            event_type=AuditEventType.POLICY_DECISION,
            reason_code="; ".join(decision.reason_codes),
            device_id=device_id,
            details=decision.to_dict(),
        )

        return ScenarioResult(
            scenario_name="Normal Admission",
            device_id=device_id,
            initial_state=initial_state,
            final_state=final_state,
            decision=decision,
            enforcement_result=None,
            audit_event_count=len(self.audit_log.get_events(device_id)),
            summary=f"Device successfully admitted: {initial_state.value} -> {final_state.value}.",
        )

    def run_scenario_insufficient_evidence(self) -> ScenarioResult:
        """Scenario 2: Insufficient Evidence Flow.

        Device connects -> Quarantined -> Missing Network Telemetry -> Kept in QUARANTINED.
        """
        device_id = "dock-dev-incomplete"
        dev = Device(device_id=device_id, mac_address="00:11:22:33:44:02", physical_port=2)

        self.engine.register_device(dev)
        initial_state = self.engine.registry.get(device_id).status

        self.audit_log.record(
            event_type=AuditEventType.DISCOVERY,
            reason_code="DEVICE_DOCKED",
            device_id=device_id,
            details={"physical_port": 2, "mac_address": "00:11:22:33:44:02"},
        )

        # Supply physical telemetry only, omitting network telemetry
        now = time.time()
        phys = [PhysicalTelemetry(device_id, 2, voltage_v=5.0, current_a=0.3, timestamp=now)]

        decision = self.engine.evaluate_admission(
            device_id, physical_telemetry=phys, network_telemetry=[], current_time=now
        )
        final_state = self.engine.registry.get(device_id).status

        self.audit_log.record(
            event_type=AuditEventType.POLICY_DECISION,
            reason_code="; ".join(decision.reason_codes),
            device_id=device_id,
            details=decision.to_dict(),
        )

        return ScenarioResult(
            scenario_name="Insufficient Evidence",
            device_id=device_id,
            initial_state=initial_state,
            final_state=final_state,
            decision=decision,
            enforcement_result=None,
            audit_event_count=len(self.audit_log.get_events(device_id)),
            summary=f"Admission deferred: device safely remains in {final_state.value}.",
        )

    def run_scenario_policy_violation_isolation(self) -> ScenarioResult:
        """Scenario 3: Policy Violation & Simulated Isolation Flow.

        Device admits -> Monitored -> Prohibited C2 endpoint accessed -> ISOLATED -> Enforcement simulated.
        """
        device_id = "dock-dev-rogue"
        dev = Device(device_id=device_id, mac_address="00:11:22:33:44:03", physical_port=3)

        # 1. Admit initially
        self.engine.register_device(dev)
        now = time.time()
        phys_ok = [PhysicalTelemetry(device_id, 3, voltage_v=5.05, current_a=0.40, timestamp=now)]
        net_ok = [
            NetworkTelemetry(
                "00:11:22:33:44:03", "192.168.1.17", "192.168.1.1", "TCP", 20, 1500, now
            )
        ]
        self.engine.evaluate_admission(device_id, phys_ok, net_ok, current_time=now)
        admitted_state = self.engine.registry.get(device_id).status

        # 2. Device exhibits severe violation: communications with prohibited C2 domain
        net_c2 = [
            NetworkTelemetry(
                "00:11:22:33:44:03", "192.168.1.17", "botnet.c2", "TCP", 25, 2048, now
            )
        ]
        decision = self.engine.evaluate_monitoring(
            device_id, physical_telemetry=[], network_telemetry=net_c2, current_time=now
        )
        final_state = self.engine.registry.get(device_id).status

        # 3. Request simulated isolation through enforcement adapter
        enforcement_result = self.adapter.isolate_device(
            device_id=device_id,
            reason=f"Policy violation: {decision.explanation}",
        )

        return ScenarioResult(
            scenario_name="Policy Violation & Isolation",
            device_id=device_id,
            initial_state=admitted_state,
            final_state=final_state,
            decision=decision,
            enforcement_result=enforcement_result,
            audit_event_count=len(self.audit_log.get_events(device_id)),
            summary=f"Severe violation detected: transitioned {admitted_state.value} -> {final_state.value} with simulated isolation.",
        )

    def run_all(self) -> List[ScenarioResult]:
        """Execute all demonstration scenarios sequentially."""
        return [
            self.run_scenario_normal_admission(),
            self.run_scenario_insufficient_evidence(),
            self.run_scenario_policy_violation_isolation(),
        ]
