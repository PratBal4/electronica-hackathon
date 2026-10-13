"""State model for the Smart Backplane Trust Engine.

Defines authoritative lifecycle states for docked devices monitored by
the Raspberry Pi Trust Engine.
"""

from enum import Enum
from typing import Set


class DeviceState(str, Enum):
    """Authoritative lifecycle state for a docked device.

    State Descriptions:
        UNKNOWN: Device detected or seen in traffic but not yet admitted or quarantined.
        QUARANTINED: Device is placed in quarantine pending evidence validation.
                     New devices start in this state.
        TRUSTED: Device has passed admission rules and telemetry bounds.
                 Only the Trust Engine can grant this state.
        ANOMALOUS: Device exhibited abnormal telemetry or network patterns
                   exceeding safe baseline thresholds.
        ISOLATED: Device has been restricted due to severe or repeated violations.
        REJECTED: Device failed admission or policy requirements permanently.
    """

    UNKNOWN = "UNKNOWN"
    QUARANTINED = "QUARANTINED"
    TRUSTED = "TRUSTED"
    ANOMALOUS = "ANOMALOUS"
    ISOLATED = "ISOLATED"
    REJECTED = "REJECTED"

    def __str__(self) -> str:
        """Return the string representation of the state value."""
        return self.value

    @classmethod
    def from_string(cls, value: str) -> "DeviceState":
        """Convert a string representation to a DeviceState.

        Performs a case-insensitive lookup after stripping whitespace.

        Args:
            value: The string representation of the state (e.g. 'QUARANTINED', 'quarantined').

        Returns:
            The matching DeviceState enum member.

        Raises:
            ValueError: If the input cannot be converted or is not a valid state.
        """
        if not isinstance(value, str):
            raise ValueError(f"State value must be a string, got {type(value).__name__}")

        normalized = value.strip().upper()
        try:
            return cls[normalized]
        except KeyError:
            valid_names = ", ".join(m.name for m in cls)
            raise ValueError(
                f"Invalid DeviceState '{value}'. Valid states are: {valid_names}"
            ) from None

    @classmethod
    def valid_states(cls) -> Set[str]:
        """Return the set of all valid state string names."""
        return {member.value for member in cls}
