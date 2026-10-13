"""Tests for AuditLog and zero-secret audit events."""

import time
import pytest

from trust_engine.audit import (
    AuditEvent,
    AuditEventType,
    AuditLog,
    sanitize_audit_data,
)


@pytest.fixture
def audit_log() -> AuditLog:
    """Fixture providing a fresh AuditLog instance."""
    return AuditLog()


def test_audit_event_recording_and_querying(audit_log: AuditLog) -> None:
    """Verify events are properly recorded with UUIDs, timestamps, and can be queried."""
    t0 = time.time()
    e1 = audit_log.record(
        event_type=AuditEventType.DISCOVERY,
        reason_code="DOCK_EVENT",
        device_id="dev-01",
        details={"port": 1},
        severity="INFO",
    )

    e2 = audit_log.record(
        event_type=AuditEventType.STATE_TRANSITION,
        reason_code="ADMISSION_APPROVED",
        device_id="dev-01",
        details={"from": "QUARANTINED", "to": "TRUSTED"},
        severity="INFO",
    )

    e3 = audit_log.record(
        event_type=AuditEventType.POLICY_DECISION,
        reason_code="INSUFFICIENT_EVIDENCE",
        device_id="dev-02",
        details={"missing": "network"},
        severity="WARNING",
    )

    assert len(audit_log) == 3
    assert e1.timestamp >= t0
    assert e1.event_type is AuditEventType.DISCOVERY

    # Query by device_id
    dev1_events = audit_log.get_events(device_id="dev-01")
    assert len(dev1_events) == 2
    assert dev1_events[0].event_id == e1.event_id
    assert dev1_events[1].event_id == e2.event_id

    # Query by event_type
    policy_events = audit_log.get_events(event_type=AuditEventType.POLICY_DECISION)
    assert len(policy_events) == 1
    assert policy_events[0].device_id == "dev-02"


def test_secret_scrubbing_guarantee() -> None:
    """Verify sensitive keys like passwords, tokens, API keys, and private keys are redacted."""
    raw_payload = {
        "device_id": "dev-01",
        "api_key": "secret_live_12345",
        "password": "SuperSecretPassword!",
        "private_key": "-----BEGIN PRIVATE KEY-----...",
        "auth_token": "bearer eyJhbGciOi...",
        "normal_metric": 42.5,
        "nested": {
            "user_data": {"user_token": "xyz789"},
            "credentials": "secret_blob",
            "safe_counter": 100,
        },
    }

    sanitized = sanitize_audit_data(raw_payload)

    assert sanitized["device_id"] == "dev-01"
    assert sanitized["normal_metric"] == 42.5
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["private_key"] == "[REDACTED]"
    assert sanitized["auth_token"] == "[REDACTED]"
    assert sanitized["nested"]["credentials"] == "[REDACTED]"
    assert sanitized["nested"]["user_data"]["user_token"] == "[REDACTED]"
    assert sanitized["nested"]["safe_counter"] == 100



def test_audit_event_serialization(audit_log: AuditLog) -> None:
    """Verify to_dict serialization for audit records."""
    event = audit_log.record(
        event_type=AuditEventType.ENFORCEMENT_RESULT,
        reason_code="ISOLATE_SIMULATED",
        device_id="dev-99",
        details={"action": "isolate"},
        severity="INFO",
    )
    d = event.to_dict()
    assert d["event_id"] == event.event_id
    assert d["event_type"] == "ENFORCEMENT_RESULT"
    assert d["device_id"] == "dev-99"
    assert d["reason_code"] == "ISOLATE_SIMULATED"
    assert d["severity"] == "INFO"
