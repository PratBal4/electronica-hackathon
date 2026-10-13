"""Tests for DeviceState enum model and conversion logic."""

import pytest
from trust_engine.states import DeviceState


def test_enum_members_exist_and_values() -> None:
    """Verify all 6 required states exist with exact uppercase values and correct spelling."""
    expected_members = {
        "UNKNOWN": "UNKNOWN",
        "QUARANTINED": "QUARANTINED",
        "TRUSTED": "TRUSTED",
        "ANOMALOUS": "ANOMALOUS",  # Specific check for correct spelling
        "ISOLATED": "ISOLATED",
        "REJECTED": "REJECTED",
    }

    assert len(DeviceState) == len(expected_members)
    for name, value in expected_members.items():
        assert hasattr(DeviceState, name)
        member = getattr(DeviceState, name)
        assert member.value == value
        assert member.name == name


def test_string_conversion() -> None:
    """Verify string conversion works directly and via helper methods."""
    assert str(DeviceState.QUARANTINED) == "QUARANTINED"
    assert str(DeviceState.ANOMALOUS) == "ANOMALOUS"

    # Direct Enum constructor conversion
    assert DeviceState("UNKNOWN") is DeviceState.UNKNOWN
    assert DeviceState("TRUSTED") is DeviceState.TRUSTED

    # from_string with case-insensitivity and whitespace trimming
    assert DeviceState.from_string("trusted") is DeviceState.TRUSTED
    assert DeviceState.from_string("  QUARANTINED  ") is DeviceState.QUARANTINED
    assert DeviceState.from_string("anomalous") is DeviceState.ANOMALOUS
    assert DeviceState.from_string("Isolated") is DeviceState.ISOLATED
    assert DeviceState.from_string("rejected") is DeviceState.REJECTED


def test_invalid_string_conversion_fails() -> None:
    """Verify invalid string conversions raise ValueError with descriptive messages."""
    with pytest.raises(ValueError, match="Invalid DeviceState"):
        DeviceState.from_string("INVALID_STATE")

    with pytest.raises(ValueError, match="Invalid DeviceState"):
        DeviceState.from_string("UNTRUSTED")

    with pytest.raises(ValueError, match="Invalid DeviceState"):
        DeviceState.from_string("")

    with pytest.raises(ValueError, match="must be a string"):
        DeviceState.from_string(None)  # type: ignore

    with pytest.raises(ValueError, match="must be a string"):
        DeviceState.from_string(12345)  # type: ignore

    with pytest.raises(ValueError):
        DeviceState("NON_EXISTENT")


def test_valid_states_set() -> None:
    """Verify valid_states helper returns all state values."""
    valid = DeviceState.valid_states()
    assert valid == {
        "UNKNOWN",
        "QUARANTINED",
        "TRUSTED",
        "ANOMALOUS",
        "ISOLATED",
        "REJECTED",
    }
