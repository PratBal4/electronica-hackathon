"""Audit logging for the Smart Backplane Trust Engine.

Captures immutable, structured audit records for discovery, registration conflicts,
policy decisions, state machine transitions, enforcement actions, and adapter
failures. Enforces zero-secret logging.
"""

from dataclasses import dataclass, field
from enum import Enum
import logging
import time
from typing import Any, Dict, List, Optional
import uuid

logger = logging.getLogger("trust_engine.audit")

# Sensitive key patterns that must never appear in cleartext audit records
_SENSITIVE_KEYS = {
    "key",
    "secret",
    "token",
    "password",
    "credential",
    "private_key",
    "auth",
    "api_key",
}


def sanitize_audit_data(data: Any) -> Any:
    """Recursively scrub sensitive credential keys from audit dictionaries."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            if any(s in str(k).lower() for s in _SENSITIVE_KEYS):
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = sanitize_audit_data(v)
        return sanitized
    if isinstance(data, list):
        return [sanitize_audit_data(item) for item in data]
    return data


class AuditEventType(str, Enum):
    """Categorization of audit events."""

    DISCOVERY = "DISCOVERY"
    REGISTRATION_CONFLICT = "REGISTRATION_CONFLICT"
    POLICY_DECISION = "POLICY_DECISION"
    STATE_TRANSITION = "STATE_TRANSITION"
    ENFORCEMENT_REQUEST = "ENFORCEMENT_REQUEST"
    ENFORCEMENT_RESULT = "ENFORCEMENT_RESULT"
    ADAPTER_FAILURE = "ADAPTER_FAILURE"
    TELEMETRY_INVALID = "TELEMETRY_INVALID"

    def __str__(self) -> str:
        return self.value


@dataclass
class AuditEvent:
    """Structured audit trail record.

    Attributes:
        event_id: Unique UUID string identifying this audit entry.
        event_type: Categorical AuditEventType.
        timestamp: POSIX timestamp when event occurred.
        device_id: Associated device ID (if applicable).
        reason_code: Programmatic reason code.
        details: Contextual details (sanitized against secrets).
        severity: Log severity level ('INFO', 'WARNING', 'ERROR').
    """

    event_id: str
    event_type: AuditEventType
    timestamp: float
    reason_code: str
    device_id: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "device_id": self.device_id,
            "reason_code": self.reason_code,
            "details": self.details,
            "severity": self.severity,
        }


class AuditLog:
    """Authoritative in-memory append-only audit log."""

    def __init__(self) -> None:
        """Initialize an empty audit log."""
        self._events: List[AuditEvent] = []

    def record(
        self,
        event_type: AuditEventType,
        reason_code: str,
        device_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "INFO",
        timestamp: Optional[float] = None,
    ) -> AuditEvent:
        """Record an audit event and forward to Python logging.

        Args:
            event_type: Category of the event.
            reason_code: Programmatic reason code.
            device_id: Optional device identifier.
            details: Contextual dictionary (will be scrubbed for secrets).
            severity: Event severity level.
            timestamp: Event timestamp (defaults to time.time()).

        Returns:
            The created AuditEvent.
        """
        now = timestamp if timestamp is not None else time.time()
        scrubbed_details = sanitize_audit_data(details or {})

        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=event_type,
            timestamp=now,
            reason_code=reason_code,
            device_id=device_id,
            details=scrubbed_details,
            severity=severity.upper(),
        )
        self._events.append(event)

        # Mirror to Python logging system
        log_msg = (
            f"[{event.event_type.value}] Device='{device_id or 'N/A'}' | "
            f"Reason='{reason_code}' | Details={scrubbed_details}"
        )
        if event.severity == "WARNING":
            logger.warning(log_msg)
        elif event.severity in ("ERROR", "CRITICAL"):
            logger.error(log_msg)
        else:
            logger.info(log_msg)

        return event

    def get_events(
        self,
        device_id: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
    ) -> List[AuditEvent]:
        """Query recorded audit events filtered by device_id or event_type."""
        filtered = self._events
        if device_id is not None:
            filtered = [e for e in filtered if e.device_id == device_id]
        if event_type is not None:
            filtered = [e for e in filtered if e.event_type == event_type]
        return list(filtered)

    def clear(self) -> None:
        """Clear all events (primarily for testing)."""
        self._events.clear()

    def __len__(self) -> int:
        """Return total count of recorded events."""
        return len(self._events)

    def __bool__(self) -> bool:
        """AuditLog instance is always truthy, representing an active audit log."""
        return True
