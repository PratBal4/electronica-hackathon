"""Tests for deterministic demonstration simulator."""

import pytest

from trust_engine.policy import DecisionType
from trust_engine.simulator import ScenarioResult, Simulator
from trust_engine.states import DeviceState


@pytest.fixture
def simulator() -> Simulator:
    """Fixture providing a fresh Simulator instance."""
    return Simulator()


def test_scenario_normal_admission(simulator: Simulator) -> None:
    """Verify normal admission scenario admits compliant device to TRUSTED."""
    result = simulator.run_scenario_normal_admission()

    assert result.scenario_name == "Normal Admission"
    assert result.device_id == "dock-dev-normal"
    assert result.initial_state is DeviceState.QUARANTINED
    assert result.final_state is DeviceState.TRUSTED
    assert result.decision.decision_type is DecisionType.ALLOW
    assert result.enforcement_result is None
    assert result.audit_event_count >= 2


def test_scenario_insufficient_evidence(simulator: Simulator) -> None:
    """Verify incomplete telemetry scenario safely retains device in QUARANTINED."""
    result = simulator.run_scenario_insufficient_evidence()

    assert result.scenario_name == "Insufficient Evidence"
    assert result.device_id == "dock-dev-incomplete"
    assert result.initial_state is DeviceState.QUARANTINED
    assert result.final_state is DeviceState.QUARANTINED
    assert result.decision.decision_type is DecisionType.KEEP_QUARANTINED
    assert result.enforcement_result is None


def test_scenario_policy_violation_isolation(simulator: Simulator) -> None:
    """Verify policy violation scenario transitions device to ISOLATED with recorded simulated enforcement."""
    result = simulator.run_scenario_policy_violation_isolation()

    assert result.scenario_name == "Policy Violation & Isolation"
    assert result.device_id == "dock-dev-rogue"
    assert result.initial_state is DeviceState.TRUSTED
    assert result.final_state is DeviceState.ISOLATED
    assert result.decision.decision_type is DecisionType.ISOLATE
    assert result.enforcement_result is not None
    assert result.enforcement_result.success is True
    assert result.enforcement_result.is_simulation is True


def test_run_all_scenarios(simulator: Simulator) -> None:
    """Verify running all scenarios returns exactly 3 structured scenario results."""
    results = simulator.run_all()
    assert len(results) == 3

    scenario_names = [r.scenario_name for r in results]
    assert scenario_names == [
        "Normal Admission",
        "Insufficient Evidence",
        "Policy Violation & Isolation",
    ]

    for r in results:
        d = r.to_dict()
        assert "scenario_name" in d
        assert "initial_state" in d
        assert "final_state" in d
