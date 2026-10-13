"""Unit tests for deterministic PolicyEngine rules and decision structures."""

import pytest

from trust_engine.device import Device
from trust_engine.policy import DecisionType, PolicyConfig, PolicyEngine
from trust_engine.states import DeviceState
from trust_engine.telemetry import NetworkTelemetry, PhysicalTelemetry


@pytest.fixture
def policy_engine() -> PolicyEngine:
    """Fixture providing a fresh PolicyEngine instance."""
    return PolicyEngine()


@pytest.fixture
def device() -> Device:
    """Fixture providing a standard quarantined device."""
    return Device(
        device_id="dock-dev-01",
        mac_address="00:11:22:33:44:55",
        physical_port=1,
        status=DeviceState.QUARANTINED,
    )


def test_insufficient_evidence_keeps_quarantined(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify missing physical or network evidence leaves the device in QUARANTINED."""
    # 1. No telemetry at all
    decision_empty = policy_engine.evaluate_admission(device)
    assert decision_empty.decision_type is DecisionType.KEEP_QUARANTINED
    assert decision_empty.recommended_state is DeviceState.QUARANTINED
    assert "INSUFFICIENT_EVIDENCE" in decision_empty.reason_codes

    # 2. Only physical telemetry, missing network telemetry
    phys = [PhysicalTelemetry("dock-dev-01", 1, 5.0, 0.4, 1000.0)]
    decision_only_phys = policy_engine.evaluate_admission(
        device, physical_telemetry=phys, network_telemetry=[]
    )
    assert decision_only_phys.decision_type is DecisionType.KEEP_QUARANTINED
    assert decision_only_phys.recommended_state is DeviceState.QUARANTINED
    assert "INSUFFICIENT_EVIDENCE" in decision_only_phys.reason_codes

    # 3. Only network telemetry, missing physical telemetry
    net = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 20, 1500, 1000.0)]
    decision_only_net = policy_engine.evaluate_admission(
        device, physical_telemetry=[], network_telemetry=net
    )
    assert decision_only_net.decision_type is DecisionType.KEEP_QUARANTINED
    assert "INSUFFICIENT_EVIDENCE" in decision_only_net.reason_codes


def test_successful_admission_under_defined_rules(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify compliant physical baseline and network telemetry permits admission to TRUSTED."""
    phys = [PhysicalTelemetry("dock-dev-01", 1, 5.02, 0.45, 1000.0)]
    net = [
        NetworkTelemetry(
            source_mac="00:11:22:33:44:55",
            source_ip="192.168.1.10",
            destination="192.168.1.1",
            protocol="TCP",
            packet_count=50,
            byte_count=4000,
            timestamp=1000.0,
            destination_port=443,
        )
    ]

    decision = policy_engine.evaluate_admission(
        device, physical_telemetry=phys, network_telemetry=net, elapsed_admission_time=5.0
    )

    assert decision.decision_type is DecisionType.ALLOW
    assert decision.recommended_state is DeviceState.TRUSTED
    assert "ADMISSION_PASSED" in decision.reason_codes
    assert "evidence_summary" in decision.to_dict()
    assert decision.evidence_summary["admission_criteria_passed"] is True


def test_identity_conflict_prevents_admission(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify MAC or port conflict immediately blocks admission and rejects."""
    phys = [PhysicalTelemetry("dock-dev-01", 1, 5.0, 0.4, 1000.0)]
    net = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 10, 500, 1000.0)]

    decision = policy_engine.evaluate_admission(
        device,
        physical_telemetry=phys,
        network_telemetry=net,
        has_identity_conflict=True,
        conflict_reasons=["Port conflict: port 1 already bound to dev-999"],
    )

    assert decision.decision_type is DecisionType.REJECT
    assert decision.recommended_state is DeviceState.REJECTED
    assert "IDENTITY_CONFLICT" in decision.reason_codes
    assert "Port conflict" in decision.explanation


def test_admission_timeout_ends_attempt_without_malice(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify timeout ends admission attempt and explicitly notes it is not proof of malice."""
    phys = [PhysicalTelemetry("dock-dev-01", 1, 5.0, 0.4, 1000.0)]
    # Missing network telemetry, and time exceeded 30s timeout
    decision = policy_engine.evaluate_admission(
        device, physical_telemetry=phys, network_telemetry=[], elapsed_admission_time=35.0
    )

    assert decision.decision_type is DecisionType.REJECT
    assert decision.recommended_state is DeviceState.REJECTED
    assert "ADMISSION_TIMEOUT" in decision.reason_codes
    assert "does not prove malice" in decision.explanation


def test_physical_baseline_violation_rejects_admission(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify abnormal voltage or current outside nominal dock operating baseline fails admission."""
    # Voltage too low for nominal dock baseline (4.2V vs min 4.75V)
    phys_low_v = [PhysicalTelemetry("dock-dev-01", 1, 4.20, 0.4, 1000.0)]
    net = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 10, 500, 1000.0)]

    decision = policy_engine.evaluate_admission(
        device, physical_telemetry=phys_low_v, network_telemetry=net
    )

    assert decision.decision_type is DecisionType.REJECT
    assert "PHYSICAL_BASELINE_OUT_OF_SPEC" in decision.reason_codes
    assert "4.2V" in decision.explanation


def test_prohibited_network_rules_reject_admission(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify prohibited destinations, protocols, or ports reject admission."""
    phys = [PhysicalTelemetry("dock-dev-01", 1, 5.0, 0.4, 1000.0)]

    # Prohibited destination
    net_bad_dest = [
        NetworkTelemetry(
            "00:11:22:33:44:55", "10.0.0.2", "botnet.c2", "TCP", 10, 500, 1000.0
        )
    ]
    d1 = policy_engine.evaluate_admission(device, phys, net_bad_dest)
    assert d1.decision_type is DecisionType.REJECT
    assert "PROHIBITED_DESTINATION" in d1.reason_codes

    # Prohibited protocol
    net_bad_proto = [
        NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TELNET", 10, 500, 1000.0)
    ]
    d2 = policy_engine.evaluate_admission(device, phys, net_bad_proto)
    assert d2.decision_type is DecisionType.REJECT
    assert "PROHIBITED_PROTOCOL" in d2.reason_codes

    # Prohibited port
    net_bad_port = [
        NetworkTelemetry(
            "00:11:22:33:44:55",
            "10.0.0.2",
            "10.0.0.1",
            "TCP",
            10,
            500,
            1000.0,
            destination_port=1337,
        )
    ]
    d3 = policy_engine.evaluate_admission(device, phys, net_bad_port)
    assert d3.decision_type is DecisionType.REJECT
    assert "PROHIBITED_PORT" in d3.reason_codes


def test_mild_anomaly_does_not_automatically_reject(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify a single mild anomaly transitions to ANOMALOUS for continued observation."""
    device.status = DeviceState.TRUSTED
    # Elevated current (2.8A vs nominal max 2.5A, but within absolute safety limit 5A)
    phys_mild = [PhysicalTelemetry("dock-dev-01", 1, 5.0, 2.8, 1000.0)]

    decision = policy_engine.evaluate_monitoring(
        device, physical_telemetry=phys_mild, network_telemetry=[], prior_anomaly_count=0
    )

    assert decision.decision_type is DecisionType.ANOMALOUS
    assert decision.recommended_state is DeviceState.ANOMALOUS
    assert "MILD_ANOMALY" in decision.reason_codes
    assert "not rejected automatically" in decision.explanation


def test_repeated_anomalies_exceeding_threshold_triggers_isolation(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify repeated mild anomalies exceeding max threshold triggers ISOLATE."""
    device.status = DeviceState.ANOMALOUS
    phys_mild = [PhysicalTelemetry("dock-dev-01", 1, 5.0, 2.8, 1000.0)]

    # Prior anomaly count is 2 (max_mild_anomalies is 2), so 3rd triggers isolation
    decision = policy_engine.evaluate_monitoring(
        device, physical_telemetry=phys_mild, network_telemetry=[], prior_anomaly_count=2
    )

    assert decision.decision_type is DecisionType.ISOLATE
    assert decision.recommended_state is DeviceState.ISOLATED
    assert "REPEATED_ANOMALIES_EXCEEDED" in decision.reason_codes


def test_severe_network_violations_trigger_immediate_isolation(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify severe violations (massive data bursts or prohibited destinations) trigger ISOLATE."""
    device.status = DeviceState.TRUSTED

    # Severe data exfiltration (15 MB in window)
    net_burst = [
        NetworkTelemetry(
            "00:11:22:33:44:55",
            "10.0.0.2",
            "10.0.0.1",
            "TCP",
            1000,
            15_000_000,
            1000.0,
        )
    ]
    decision_burst = policy_engine.evaluate_monitoring(
        device, physical_telemetry=[], network_telemetry=net_burst
    )
    assert decision_burst.decision_type is DecisionType.ISOLATE
    assert decision_burst.recommended_state is DeviceState.ISOLATED
    assert "SEVERE_VIOLATION_MASSIVE_BURST" in decision_burst.reason_codes

    # Communicating with C2 botnet node
    net_c2 = [
        NetworkTelemetry(
            "00:11:22:33:44:55", "10.0.0.2", "botnet.c2", "TCP", 10, 500, 1000.0
        )
    ]
    decision_c2 = policy_engine.evaluate_monitoring(
        device, physical_telemetry=[], network_telemetry=net_c2
    )
    assert decision_c2.decision_type is DecisionType.ISOLATE
    assert "SEVERE_VIOLATION_PROHIBITED_DESTINATION" in decision_c2.reason_codes


def test_normal_monitoring_maintains_trusted(
    policy_engine: PolicyEngine, device: Device
) -> None:
    """Verify normal telemetry during monitoring maintains TRUSTED status."""
    device.status = DeviceState.TRUSTED
    phys = [PhysicalTelemetry("dock-dev-01", 1, 5.0, 0.4, 1000.0)]
    net = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 50, 4000, 1000.0)]

    decision = policy_engine.evaluate_monitoring(
        device, physical_telemetry=phys, network_telemetry=net, prior_anomaly_count=0
    )
    assert decision.decision_type is DecisionType.ALLOW
    assert decision.recommended_state is DeviceState.TRUSTED
    assert "BEHAVIOR_NORMAL" in decision.reason_codes
