"""Tests for SimulatedEnforcementAdapter safety, failure handling, and validation."""

import os
import subprocess
from unittest.mock import patch
import pytest

from trust_engine.audit import AuditEventType, AuditLog
from trust_engine.device import Device
from trust_engine.enforcement import (
    EnforcementActionType,
    EnforcementResult,
    SimulatedEnforcementAdapter,
)
from trust_engine.registry import DeviceRegistry


@pytest.fixture
def registry() -> DeviceRegistry:
    """Fixture providing a populated registry."""
    reg = DeviceRegistry()
    reg.register(Device("dev-01", "00:11:22:33:44:55", 1))
    return reg


@pytest.fixture
def audit_log() -> AuditLog:
    """Fixture providing an audit log."""
    return AuditLog()


@pytest.fixture
def adapter(registry: DeviceRegistry, audit_log: AuditLog) -> SimulatedEnforcementAdapter:
    """Fixture providing a simulated enforcement adapter."""
    return SimulatedEnforcementAdapter(registry=registry, audit_log=audit_log)


def test_isolate_device_recorded_successfully(adapter: SimulatedEnforcementAdapter) -> None:
    """Verify isolate_device records simulated action with explicit safety flag."""
    res = adapter.isolate_device("dev-01", reason="Excessive traffic exfiltration")

    assert res.success is True
    assert res.action is EnforcementActionType.ISOLATE_DEVICE
    assert res.target == "dev-01"
    assert res.is_simulation is True
    assert len(adapter.recorded_actions) == 1
    assert adapter.recorded_actions[0].target == "dev-01"


def test_restore_quarantine_recorded_successfully(adapter: SimulatedEnforcementAdapter) -> None:
    """Verify restore_quarantine records simulated action."""
    res = adapter.restore_quarantine("dev-01", reason="Re-evaluation requested")

    assert res.success is True
    assert res.action is EnforcementActionType.RESTORE_QUARANTINE
    assert res.is_simulation is True


def test_set_port_power_recorded_successfully(adapter: SimulatedEnforcementAdapter) -> None:
    """Verify set_port_power records simulated power request without manipulating GPIO."""
    res = adapter.set_port_power(physical_port=1, enabled=False, reason="Safety shutdown")

    assert res.success is True
    assert res.action is EnforcementActionType.SET_PORT_POWER
    assert res.target == "1"
    assert res.details["requested_power"] == "POWER_OFF"
    assert res.is_simulation is True


def test_unknown_device_fails_safely(adapter: SimulatedEnforcementAdapter) -> None:
    """Verify unknown device ID fails safely with clear error message without raising exceptions."""
    res = adapter.isolate_device("unknown-dev", reason="Policy violation")

    assert res.success is False
    assert "Unknown device ID" in (res.error_message or "")
    assert res.is_simulation is True


def test_invalid_arguments_fail_safely(adapter: SimulatedEnforcementAdapter) -> None:
    """Verify blank IDs, blank reasons, and invalid port formats fail safely."""
    # Blank device ID
    r1 = adapter.isolate_device("", reason="Valid reason")
    assert r1.success is False
    assert "device_id must be a non-empty string" in (r1.error_message or "")

    # Blank reason
    r2 = adapter.isolate_device("dev-01", reason="   ")
    assert r2.success is False
    assert "reason must be an explicit non-empty string" in (r2.error_message or "")

    # Invalid port (negative or 0)
    r3 = adapter.set_port_power(physical_port=0, enabled=True, reason="Turn on")
    assert r3.success is False
    assert "must be positive int" in (r3.error_message or "")

    # Bool port
    r4 = adapter.set_port_power(physical_port=True, enabled=True, reason="Turn on")
    assert r4.success is False


def test_simulated_adapter_failure_handled_safely(registry: DeviceRegistry, audit_log: AuditLog) -> None:
    """Verify adapter communications failures are captured and audited as ADAPTER_FAILURE."""
    failing_adapter = SimulatedEnforcementAdapter(
        registry=registry, audit_log=audit_log, simulate_failure=True
    )

    res = failing_adapter.isolate_device("dev-01", reason="Test fault injection")
    assert res.success is False
    assert "Simulated adapter communication failure" in (res.error_message or "")

    # Audit log must have recorded ADAPTER_FAILURE
    events = audit_log.get_events(event_type=AuditEventType.ADAPTER_FAILURE)
    assert len(events) == 1
    assert events[0].reason_code == "ADAPTER_COMMUNICATION_ERROR"


def test_safety_guarantee_no_system_or_gpio_calls_occurred(adapter: SimulatedEnforcementAdapter) -> None:
    """Mathematically prove that no subprocess, shell commands, or os calls occur during enforcement."""
    with patch.object(subprocess, "run") as mock_sub_run, \
         patch.object(subprocess, "Popen") as mock_sub_popen, \
         patch.object(os, "system") as mock_os_system:

        adapter.isolate_device("dev-01", reason="Test system isolation")
        adapter.restore_quarantine("dev-01", reason="Test restore")
        adapter.set_port_power(1, enabled=True, reason="Test port power")

        mock_sub_run.assert_not_called()
        mock_sub_popen.assert_not_called()
        mock_os_system.assert_not_called()
