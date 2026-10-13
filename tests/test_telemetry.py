"""Tests for telemetry schemas and validation."""

import math
import time
import pytest

from trust_engine.telemetry import (
    NetworkBoundsConfig,
    NetworkTelemetry,
    PhysicalBoundsConfig,
    PhysicalTelemetry,
    TelemetryValidationError,
    TelemetryValidator,
    ValidationResult,
    validate_network_telemetry,
    validate_physical_telemetry,
)


# --- 1. Valid Records ---


def test_valid_physical_telemetry_accepted() -> None:
    """Verify that a compliant physical telemetry record passes validation."""
    now = time.time()
    telemetry = PhysicalTelemetry(
        device_id="dock-dev-01",
        physical_port=1,
        voltage_v=5.05,
        current_a=0.45,
        timestamp=now,
        temperature_c=36.5,
    )

    result = validate_physical_telemetry(telemetry, current_time=now)
    assert result.is_valid is True
    assert len(result.errors) == 0
    # Must not raise
    result.raise_if_invalid()


def test_valid_physical_telemetry_without_optional_temperature() -> None:
    """Verify physical telemetry with temperature_c=None is accepted."""
    now = time.time()
    telemetry = PhysicalTelemetry(
        device_id="dock-dev-02",
        physical_port="port-2",
        voltage_v=5.0,
        current_a=1.2,
        timestamp=now,
        temperature_c=None,
    )

    result = validate_physical_telemetry(telemetry, current_time=now)
    assert result.is_valid is True
    assert len(result.errors) == 0


def test_valid_network_telemetry_accepted() -> None:
    """Verify that a compliant network telemetry record passes validation."""
    now = time.time()
    telemetry = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="TCP",
        packet_count=150,
        byte_count=14200,
        timestamp=now,
        device_id="dock-dev-01",
        physical_port=1,
        source_port=49152,
        destination_port=443,
        window_duration_s=10.0,
    )

    result = validate_network_telemetry(telemetry, current_time=now)
    assert result.is_valid is True
    assert len(result.errors) == 0
    result.raise_if_invalid()


# --- 2. Type & Missing Field Validation ---


def test_physical_telemetry_wrong_type_rejected() -> None:
    """Verify non-PhysicalTelemetry objects are rejected."""
    result = validate_physical_telemetry({"voltage_v": 5.0})
    assert result.is_valid is False
    assert "Expected PhysicalTelemetry instance" in result.errors[0]


def test_physical_telemetry_missing_or_invalid_fields() -> None:
    """Verify empty device_id, bool port, and non-numeric voltage/current are rejected."""
    now = time.time()

    # Empty device_id
    t1 = PhysicalTelemetry(
        device_id="   ",
        physical_port=1,
        voltage_v=5.0,
        current_a=0.5,
        timestamp=now,
    )
    r1 = validate_physical_telemetry(t1, current_time=now)
    assert r1.is_valid is False
    assert any("device_id must be a non-empty string" in e for e in r1.errors)

    # Boolean physical_port (bool is instance of int in Python)
    t2 = PhysicalTelemetry(
        device_id="dev-1",
        physical_port=True,  # type: ignore
        voltage_v=5.0,
        current_a=0.5,
        timestamp=now,
    )
    r2 = validate_physical_telemetry(t2, current_time=now)
    assert r2.is_valid is False
    assert any("physical_port" in e for e in r2.errors)

    # Non-numeric voltage (e.g. string or bool)
    t3 = PhysicalTelemetry(
        device_id="dev-1",
        physical_port=1,
        voltage_v="5.0",  # type: ignore
        current_a=0.5,
        timestamp=now,
    )
    r3 = validate_physical_telemetry(t3, current_time=now)
    assert r3.is_valid is False
    assert any("voltage_v must be numeric" in e for e in r3.errors)

    t4 = PhysicalTelemetry(
        device_id="dev-1",
        physical_port=1,
        voltage_v=False,  # type: ignore
        current_a=0.5,
        timestamp=now,
    )
    r4 = validate_physical_telemetry(t4, current_time=now)
    assert r4.is_valid is False
    assert any("voltage_v must be numeric" in e for e in r4.errors)


def test_network_telemetry_wrong_types_rejected() -> None:
    """Verify type checking on required network telemetry fields."""
    now = time.time()

    # Empty MAC
    net1 = NetworkTelemetry(
        source_mac="",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="TCP",
        packet_count=10,
        byte_count=1000,
        timestamp=now,
    )
    assert validate_network_telemetry(net1, current_time=now).is_valid is False

    # Boolean packet_count
    net2 = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="TCP",
        packet_count=True,  # type: ignore
        byte_count=1000,
        timestamp=now,
    )
    r2 = validate_network_telemetry(net2, current_time=now)
    assert r2.is_valid is False
    assert any("packet_count must be an integer" in e for e in r2.errors)


# --- 3. Out-of-Range and Configurable Bounds ---


def test_physical_telemetry_out_of_bounds() -> None:
    """Verify voltages and currents outside sensible boundaries are rejected."""
    now = time.time()

    # Voltage too high (e.g. 28V on 24V dock max)
    t_high_v = PhysicalTelemetry("dev-1", 1, voltage_v=28.0, current_a=0.5, timestamp=now)
    res_high_v = validate_physical_telemetry(t_high_v, current_time=now)
    assert res_high_v.is_valid is False
    assert any("voltage_v" in e and "out of bounds" in e for e in res_high_v.errors)

    # Voltage negative
    t_neg_v = PhysicalTelemetry("dev-1", 1, voltage_v=-1.0, current_a=0.5, timestamp=now)
    assert validate_physical_telemetry(t_neg_v, current_time=now).is_valid is False

    # Current too high (e.g. 10A on 5A max)
    t_high_c = PhysicalTelemetry("dev-1", 1, voltage_v=5.0, current_a=10.0, timestamp=now)
    res_high_c = validate_physical_telemetry(t_high_c, current_time=now)
    assert res_high_c.is_valid is False
    assert any("current_a" in e and "out of bounds" in e for e in res_high_c.errors)

    # Temperature out of bounds
    t_temp = PhysicalTelemetry(
        "dev-1", 1, voltage_v=5.0, current_a=0.5, timestamp=now, temperature_c=150.0
    )
    res_temp = validate_physical_telemetry(t_temp, current_time=now)
    assert res_temp.is_valid is False
    assert any("temperature_c" in e and "out of bounds" in e for e in res_temp.errors)


def test_physical_telemetry_custom_configurable_bounds() -> None:
    """Verify strict custom bounds (e.g. narrow USB 5V rail 4.75V - 5.25V)."""
    custom_bounds = PhysicalBoundsConfig(
        min_voltage_v=4.75,
        max_voltage_v=5.25,
        min_current_a=0.05,
        max_current_a=2.0,
    )
    now = time.time()

    # 4.6V is valid under default 0-24V, but invalid under strict USB bounds
    t = PhysicalTelemetry("dev-1", 1, voltage_v=4.60, current_a=0.5, timestamp=now)
    res = validate_physical_telemetry(t, bounds=custom_bounds, current_time=now)
    assert res.is_valid is False
    assert any("voltage_v 4.6 V out of bounds" in e for e in res.errors)


def test_network_telemetry_out_of_bounds() -> None:
    """Verify negative packet counts and out-of-range ports are rejected."""
    now = time.time()

    # Negative packet count
    net_neg = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="TCP",
        packet_count=-5,
        byte_count=1000,
        timestamp=now,
    )
    assert validate_network_telemetry(net_neg, current_time=now).is_valid is False

    # Out of range port (0 or >65535)
    net_bad_port = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="TCP",
        packet_count=10,
        byte_count=1000,
        timestamp=now,
        source_port=70000,
    )
    res_port = validate_network_telemetry(net_bad_port, current_time=now)
    assert res_port.is_valid is False
    assert any("source_port 70000 out of range" in e for e in res_port.errors)


# --- 4. Rejection of NaN and Infinity (Finite Numbers) ---


def test_physical_telemetry_rejects_nan_and_infinity() -> None:
    """Verify that NaN and Infinity in any numeric field are rejected."""
    now = time.time()

    # NaN voltage
    t_nan_v = PhysicalTelemetry("dev-1", 1, voltage_v=float("nan"), current_a=0.5, timestamp=now)
    r_nan_v = validate_physical_telemetry(t_nan_v, current_time=now)
    assert r_nan_v.is_valid is False
    assert any("voltage_v must be a finite number" in e for e in r_nan_v.errors)

    # +Infinity current
    t_inf_c = PhysicalTelemetry("dev-1", 1, voltage_v=5.0, current_a=float("inf"), timestamp=now)
    r_inf_c = validate_physical_telemetry(t_inf_c, current_time=now)
    assert r_inf_c.is_valid is False
    assert any("current_a must be a finite number" in e for e in r_inf_c.errors)

    # -Infinity temperature
    t_ninf_t = PhysicalTelemetry(
        "dev-1", 1, voltage_v=5.0, current_a=0.5, timestamp=now, temperature_c=float("-inf")
    )
    r_ninf_t = validate_physical_telemetry(t_ninf_t, current_time=now)
    assert r_ninf_t.is_valid is False
    assert any("temperature_c must be a finite number" in e for e in r_ninf_t.errors)

    # NaN timestamp
    t_nan_ts = PhysicalTelemetry("dev-1", 1, voltage_v=5.0, current_a=0.5, timestamp=float("nan"))
    r_nan_ts = validate_physical_telemetry(t_nan_ts, current_time=now)
    assert r_nan_ts.is_valid is False
    assert any("timestamp must be a finite number" in e for e in r_nan_ts.errors)


def test_network_telemetry_rejects_nan_and_infinity() -> None:
    """Verify NaN/Infinity in network telemetry timestamp or window duration are rejected."""
    now = time.time()

    net_nan_ts = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="TCP",
        packet_count=10,
        byte_count=1000,
        timestamp=float("nan"),
    )
    r = validate_network_telemetry(net_nan_ts, current_time=now)
    assert r.is_valid is False
    assert any("timestamp must be a finite number" in e for e in r.errors)

    net_inf_win = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="TCP",
        packet_count=10,
        byte_count=1000,
        timestamp=now,
        window_duration_s=float("inf"),
    )
    r2 = validate_network_telemetry(net_inf_win, current_time=now)
    assert r2.is_valid is False
    assert any("window_duration_s must be a positive finite number" in e for e in r2.errors)


# --- 5. Freshness and Stale Data ---


def test_physical_telemetry_stale_reading_rejected() -> None:
    """Verify stale physical readings older than max_age_seconds are rejected."""
    now = 1000.0
    stale_time = now - 120.0  # 120 seconds old (default max is 60s)

    telemetry = PhysicalTelemetry("dev-1", 1, voltage_v=5.0, current_a=0.5, timestamp=stale_time)
    result = validate_physical_telemetry(telemetry, current_time=now)

    assert result.is_valid is False
    assert any("Telemetry is stale" in e for e in result.errors)


def test_physical_telemetry_future_timestamp_rejected() -> None:
    """Verify timestamps significantly ahead of reference clock are rejected."""
    now = 1000.0
    future_time = now + 30.0  # 30 seconds into the future (exceeds max skew of 5s)

    telemetry = PhysicalTelemetry("dev-1", 1, voltage_v=5.0, current_a=0.5, timestamp=future_time)
    result = validate_physical_telemetry(telemetry, current_time=now)

    assert result.is_valid is False
    assert any("future" in e for e in result.errors)


def test_network_telemetry_stale_reading_rejected() -> None:
    """Verify stale network readings are rejected."""
    now = 2000.0
    stale_time = now - 90.0

    telemetry = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="TCP",
        packet_count=10,
        byte_count=1000,
        timestamp=stale_time,
    )
    result = validate_network_telemetry(telemetry, current_time=now)

    assert result.is_valid is False
    assert any("Telemetry is stale" in e for e in result.errors)


# --- 6. Optional Network Fields ---


def test_network_telemetry_optional_fields_behavior() -> None:
    """Verify optional network telemetry fields defaults and explicit valid values."""
    now = time.time()

    # Omitted optional fields default to None
    net_minimal = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="UDP",
        packet_count=5,
        byte_count=320,
        timestamp=now,
    )
    assert net_minimal.device_id is None
    assert net_minimal.physical_port is None
    assert net_minimal.source_port is None
    assert net_minimal.destination_port is None
    assert net_minimal.window_duration_s is None

    result_min = validate_network_telemetry(net_minimal, current_time=now)
    assert result_min.is_valid is True

    # Explicit invalid optional fields
    net_bad_mac_assoc = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="192.168.1.1",
        protocol="UDP",
        packet_count=5,
        byte_count=320,
        timestamp=now,
        device_id="   ",  # invalid blank device_id
        source_port=0,    # invalid port
    )
    result_bad = validate_network_telemetry(net_bad_mac_assoc, current_time=now)
    assert result_bad.is_valid is False
    assert any("device_id must be None or a non-empty string" in e for e in result_bad.errors)
    assert any("source_port 0 out of range" in e for e in result_bad.errors)


# --- 7. ValidationResult and Exceptions ---


def test_validation_result_raise_if_invalid() -> None:
    """Verify raise_if_invalid raises TelemetryValidationError with formatted messages."""
    res_fail = ValidationResult(is_valid=False, errors=["error 1", "error 2"])
    with pytest.raises(TelemetryValidationError, match="error 1; error 2"):
        res_fail.raise_if_invalid()

    res_pass = ValidationResult(is_valid=True)
    # Should not raise
    res_pass.raise_if_invalid()


def test_telemetry_serialization() -> None:
    """Verify to_dict serialization for physical and network records."""
    t_phys = PhysicalTelemetry("d1", 1, 5.0, 0.5, 1000.0, 32.0)
    d_phys = t_phys.to_dict()
    assert d_phys == {
        "device_id": "d1",
        "physical_port": 1,
        "voltage_v": 5.0,
        "current_a": 0.5,
        "timestamp": 1000.0,
        "temperature_c": 32.0,
    }

    t_net = NetworkTelemetry("mac", "1.1.1.1", "2.2.2.2", "TCP", 10, 500, 1000.0)
    d_net = t_net.to_dict()
    assert d_net["source_mac"] == "mac"
    assert d_net["packet_count"] == 10
    assert d_net["source_port"] is None
