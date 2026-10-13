"""Integration tests for TrustEngine orchestration and state transitions."""

import time
import pytest

from trust_engine.device import Device
from trust_engine.engine import (
    ALLOWED_TRANSITIONS,
    IllegalStateTransitionError,
    TrustEngine,
)
from trust_engine.policy import DecisionType, PolicyConfig, PolicyEngine
from trust_engine.registry import DeviceRegistry
from trust_engine.states import DeviceState
from trust_engine.telemetry import NetworkTelemetry, PhysicalTelemetry


@pytest.fixture
def engine() -> TrustEngine:
    """Fixture providing a fresh TrustEngine instance."""
    return TrustEngine()


def test_allowed_transitions_table_integrity() -> None:
    """Verify ALLOWED_TRANSITIONS matches the specification exactly."""
    assert ALLOWED_TRANSITIONS[DeviceState.UNKNOWN] == {DeviceState.QUARANTINED}
    assert ALLOWED_TRANSITIONS[DeviceState.QUARANTINED] == {
        DeviceState.TRUSTED,
        DeviceState.REJECTED,
    }
    assert ALLOWED_TRANSITIONS[DeviceState.TRUSTED] == {
        DeviceState.ANOMALOUS,
        DeviceState.ISOLATED,
    }
    assert ALLOWED_TRANSITIONS[DeviceState.ANOMALOUS] == {
        DeviceState.ISOLATED,
        DeviceState.TRUSTED,
    }
    assert ALLOWED_TRANSITIONS[DeviceState.ISOLATED] == {DeviceState.QUARANTINED}
    assert ALLOWED_TRANSITIONS[DeviceState.REJECTED] == set()


def test_illegal_state_transitions_are_rejected(engine: TrustEngine) -> None:
    """Verify illegal transitions violate transition rules and raise IllegalStateTransitionError."""
    dev = Device(device_id="dev-01", mac_address="00:11:22:33:44:55", physical_port=1)
    engine.register_device(dev)  # starts in QUARANTINED

    # 1. QUARANTINED -> ISOLATED is illegal (must be evaluated, cannot skip to isolated without anomaly/trust)
    with pytest.raises(IllegalStateTransitionError, match="Illegal state transition"):
        engine.transition_device("dev-01", DeviceState.ISOLATED, reason="Skipping directly to isolated")

    # 2. QUARANTINED -> ANOMALOUS is illegal
    with pytest.raises(IllegalStateTransitionError, match="Illegal state transition"):
        engine.transition_device("dev-01", DeviceState.ANOMALOUS, reason="Direct anomaly transition")

    # 3. Transition without reason is rejected
    with pytest.raises(ValueError, match="non-empty reason"):
        engine.transition_device("dev-01", DeviceState.TRUSTED, reason="")


def test_only_trust_engine_can_mark_device_trusted(engine: TrustEngine) -> None:
    """Verify registration never grants TRUSTED; only engine admission can transition to TRUSTED."""
    rogue = Device(
        device_id="rogue-01",
        mac_address="DE:AD:BE:EF:00:01",
        physical_port=1,
        status=DeviceState.TRUSTED,
    )
    reg_dev = engine.register_device(rogue)
    assert reg_dev.status is DeviceState.QUARANTINED
    assert engine.registry.get("rogue-01").status is DeviceState.QUARANTINED


def test_engine_admission_insufficient_evidence_keeps_quarantined(
    engine: TrustEngine,
) -> None:
    """Verify admission with insufficient evidence maintains QUARANTINED status in registry."""
    dev = Device("dev-01", "00:11:22:33:44:55", 1)
    engine.register_device(dev)

    decision = engine.evaluate_admission("dev-01", physical_telemetry=[], network_telemetry=[])

    assert decision.decision_type is DecisionType.KEEP_QUARANTINED
    assert engine.registry.get("dev-01").status is DeviceState.QUARANTINED


def test_engine_admission_success_transitions_to_trusted(engine: TrustEngine) -> None:
    """Verify admission under compliant evidence transitions device authoritatively to TRUSTED."""
    dev = Device("dev-01", "00:11:22:33:44:55", 1)
    engine.register_device(dev)
    now = time.time()

    phys = [PhysicalTelemetry("dev-01", 1, 5.0, 0.35, now)]
    net = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 25, 2000, now)]

    decision = engine.evaluate_admission("dev-01", phys, net, current_time=now)

    assert decision.decision_type is DecisionType.ALLOW
    assert engine.registry.get("dev-01").status is DeviceState.TRUSTED


def test_engine_admission_identity_conflict_transitions_to_rejected(
    engine: TrustEngine,
) -> None:
    """Verify physical port conflict prevents admission and transitions device to REJECTED."""
    dev1 = Device("dev-01", "00:11:22:33:44:55", 1)
    dev2 = Device("dev-02", "AA:BB:CC:DD:EE:FF", 1)  # Conflicting physical port 1
    engine.register_device(dev1)
    engine.register_device(dev2)
    now = time.time()

    phys = [PhysicalTelemetry("dev-02", 1, 5.0, 0.35, now)]
    net = [NetworkTelemetry("AA:BB:CC:DD:EE:FF", "10.0.0.3", "10.0.0.1", "TCP", 10, 500, now)]

    decision = engine.evaluate_admission("dev-02", phys, net, current_time=now)

    assert decision.decision_type is DecisionType.REJECT
    assert engine.registry.get("dev-02").status is DeviceState.REJECTED


def test_engine_admission_timeout_transitions_to_rejected(
    engine: TrustEngine,
) -> None:
    """Verify admission timing out transitions device to REJECTED with clear reason."""
    dev = Device("dev-01", "00:11:22:33:44:55", 1)
    engine.register_device(dev)

    # 40 seconds later without telemetry
    future_time = engine._admission_start_times["dev-01"] + 40.0
    decision = engine.evaluate_admission("dev-01", [], [], current_time=future_time)

    assert decision.decision_type is DecisionType.REJECT
    assert engine.registry.get("dev-01").status is DeviceState.REJECTED
    assert "ADMISSION_TIMEOUT" in decision.reason_codes


def test_engine_monitoring_mild_anomaly_transitions_to_anomalous(
    engine: TrustEngine,
) -> None:
    """Verify mild current elevation transitions TRUSTED device to ANOMALOUS for observation."""
    dev = Device("dev-01", "00:11:22:33:44:55", 1)
    engine.register_device(dev)
    now = time.time()

    # First admit to TRUSTED
    phys_ok = [PhysicalTelemetry("dev-01", 1, 5.0, 0.4, now)]
    net_ok = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 10, 500, now)]
    engine.evaluate_admission("dev-01", phys_ok, net_ok, current_time=now)
    assert engine.registry.get("dev-01").status is DeviceState.TRUSTED

    # Observe mild current surge (2.8A vs nominal max 2.5A)
    phys_surge = [PhysicalTelemetry("dev-01", 1, 5.0, 2.8, now)]
    decision = engine.evaluate_monitoring("dev-01", phys_surge, [], current_time=now)

    assert decision.decision_type is DecisionType.ANOMALOUS
    assert engine.registry.get("dev-01").status is DeviceState.ANOMALOUS
    assert engine.get_anomaly_count("dev-01") == 1


def test_engine_monitoring_repeated_anomalies_transitions_to_isolated(
    engine: TrustEngine,
) -> None:
    """Verify repeated anomalies exceeding threshold transitions device from ANOMALOUS to ISOLATED."""
    dev = Device("dev-01", "00:11:22:33:44:55", 1)
    engine.register_device(dev)
    now = time.time()

    # Admit
    phys_ok = [PhysicalTelemetry("dev-01", 1, 5.0, 0.4, now)]
    net_ok = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 10, 500, now)]
    engine.evaluate_admission("dev-01", phys_ok, net_ok, current_time=now)

    phys_surge = [PhysicalTelemetry("dev-01", 1, 5.0, 2.8, now)]

    # Anomaly 1 -> ANOMALOUS
    engine.evaluate_monitoring("dev-01", phys_surge, [], current_time=now)
    assert engine.registry.get("dev-01").status is DeviceState.ANOMALOUS

    # Anomaly 2 -> Still ANOMALOUS (count=2)
    engine.evaluate_monitoring("dev-01", phys_surge, [], current_time=now)
    assert engine.registry.get("dev-01").status is DeviceState.ANOMALOUS

    # Anomaly 3 -> Exceeds max_mild_anomalies (2) -> ISOLATED!
    decision3 = engine.evaluate_monitoring("dev-01", phys_surge, [], current_time=now)
    assert decision3.decision_type is DecisionType.ISOLATE
    assert engine.registry.get("dev-01").status is DeviceState.ISOLATED


def test_engine_monitoring_severe_violation_transitions_to_isolated(
    engine: TrustEngine,
) -> None:
    """Verify severe network violation (prohibited C2 destination) immediately isolates device."""
    dev = Device("dev-01", "00:11:22:33:44:55", 1)
    engine.register_device(dev)
    now = time.time()

    # Admit
    phys_ok = [PhysicalTelemetry("dev-01", 1, 5.0, 0.4, now)]
    net_ok = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 10, 500, now)]
    engine.evaluate_admission("dev-01", phys_ok, net_ok, current_time=now)
    assert engine.registry.get("dev-01").status is DeviceState.TRUSTED

    # Traffic directed to botnet.c2
    net_c2 = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "botnet.c2", "TCP", 10, 500, now)]
    decision = engine.evaluate_monitoring("dev-01", [], net_c2, current_time=now)

    assert decision.decision_type is DecisionType.ISOLATE
    assert engine.registry.get("dev-01").status is DeviceState.ISOLATED


def test_engine_transition_history_audit(engine: TrustEngine) -> None:
    """Verify every transition is recorded with timestamp, states, and explicit reasons."""
    dev = Device("dev-01", "00:11:22:33:44:55", 1)
    engine.register_device(dev)
    now = time.time()

    phys_ok = [PhysicalTelemetry("dev-01", 1, 5.0, 0.4, now)]
    net_ok = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.2", "10.0.0.1", "TCP", 10, 500, now)]
    engine.evaluate_admission("dev-01", phys_ok, net_ok, current_time=now)

    history = engine.get_transition_history("dev-01")
    assert len(history) == 2
    assert history[0]["to_state"] == "QUARANTINED"
    assert history[1]["from_state"] == "QUARANTINED"
    assert history[1]["to_state"] == "TRUSTED"
    assert "Admission approved" in history[1]["reason"]
