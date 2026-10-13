"""Unit and integration tests for ESP32 transport, frame parser, and ingestion pipeline.

Tests verify:
- CRC-32 calculation and verification across canonical encodings.
- Serialization and framing of sensor readings.
- Stream chunking, arbitrary slicing, and stream reassembly.
- Line ending variations (LF and CRLF).
- Corrupt CRC detection and rejection (UART line noise simulation).
- Protocol version enforcement.
- Missing fields, invalid types, and non-finite numbers (NaN/Inf).
- Sequence monotonicity tracking and reset handling.
- Buffer overflow protection against runaway / delimiter-less streams.
- Device resolution via static port map and DeviceRegistry.
- Downstream physical bounds validation integration.
- Audit logging of frame and transport errors.
- Synthetic stream generation via SyntheticESP32Source.
"""

import json
import math
import time
import pytest

from trust_engine.audit import AuditEventType, AuditLog
from trust_engine.device import Device
from trust_engine.esp32_transport import (
    CURRENT_PROTOCOL_VERSION,
    ESP32Frame,
    ESP32FrameParser,
    FrameErrorReason,
    SyntheticESP32Source,
    compute_frame_crc32,
    format_esp32_frame,
)
from trust_engine.registry import DeviceRegistry
from trust_engine.telemetry import PhysicalBoundsConfig, TelemetryValidator


def test_compute_frame_crc32_canonical_and_deterministic():
    """Verify compute_frame_crc32 produces deterministic 8-character hex digests."""
    payload1 = {"v": 1, "seq": 100, "port": 1, "voltage_v": 5.0, "current_a": 0.5, "timestamp": 1700000000.0}
    # Payload with different key ordering and existing crc32 field
    payload2 = {"timestamp": 1700000000.0, "current_a": 0.5, "port": 1, "seq": 100, "v": 1, "voltage_v": 5.0, "crc32": "deadbeef"}

    crc1 = compute_frame_crc32(payload1)
    crc2 = compute_frame_crc32(payload2)

    assert len(crc1) == 8
    assert crc1 == crc2
    assert crc1 == crc1.lower()


def test_format_esp32_frame():
    """Verify format_esp32_frame produces valid newline-terminated JSON with CRC."""
    frame = ESP32Frame(
        version=CURRENT_PROTOCOL_VERSION,
        sequence=42,
        port=1,
        voltage_v=5.12,
        current_a=0.34,
        timestamp=1700000000.0,
        temperature_c=36.0,
        device_id="dock-dev-01",
    )
    line = format_esp32_frame(frame, include_crc=True)

    assert line.endswith("\n")
    data = json.loads(line)
    assert data["v"] == 1
    assert data["seq"] == 42
    assert data["port"] == 1
    assert data["voltage_v"] == 5.12
    assert data["current_a"] == 0.34
    assert data["timestamp"] == 1700000000.0
    assert data["temp_c"] == 36.0
    assert data["device_id"] == "dock-dev-01"
    assert "crc32" in data
    assert data["crc32"] == compute_frame_crc32(data)


def test_parse_valid_frame_line():
    """Verify parse_line extracts ESP32Frame and valid PhysicalTelemetry."""
    now = time.time()
    source = SyntheticESP32Source()
    line = source.make_frame(port=1, voltage_v=5.05, current_a=0.45, temp_c=35.0, timestamp=now, device_id="dev-1")

    parser = ESP32FrameParser()
    result = parser.parse_line(line.strip())

    assert result.is_success
    assert result.error is None
    assert result.frame is not None
    assert result.telemetry is not None

    assert result.telemetry.device_id == "dev-1"
    assert result.telemetry.physical_port == 1
    assert result.telemetry.voltage_v == 5.05
    assert result.telemetry.current_a == 0.45
    assert result.telemetry.temperature_c == 35.0
    assert result.telemetry.timestamp == now

    assert parser.stats["valid_frames"] == 1
    assert parser.stats["corrupt_frames"] == 0


def test_stream_chunking_arbitrary_sizes():
    """Verify that splitting a frame across tiny chunks reassembles correctly."""
    now = time.time()
    source = SyntheticESP32Source()
    frame_str = source.make_frame(port=2, voltage_v=5.10, current_a=0.25, timestamp=now, device_id="dev-2")

    chunks = source.make_chunked_stream(frame_str, chunk_size=5)
    assert len(chunks) > 5  # Ensure frame was split into many tiny chunks

    parser = ESP32FrameParser()
    all_results = []
    for chunk in chunks:
        res = parser.feed(chunk)
        all_results.extend(res)

    # All intermediate chunks yield nothing until the newline arrives
    assert len(all_results) == 1
    assert all_results[0].is_success
    assert all_results[0].telemetry.device_id == "dev-2"
    assert all_results[0].telemetry.physical_port == 2


def test_multiple_frames_in_single_chunk():
    """Verify feeding multiple newline-separated frames in one single chunk."""
    now = time.time()
    source = SyntheticESP32Source(start_seq=10)
    f1 = source.make_frame(port=1, voltage_v=5.0, current_a=0.3, timestamp=now, device_id="dev-1")
    f2 = source.make_frame(port=1, voltage_v=5.02, current_a=0.32, timestamp=now, device_id="dev-1")
    f3 = source.make_frame(port=1, voltage_v=5.04, current_a=0.31, timestamp=now, device_id="dev-1")

    combined_chunk = (f1 + f2 + f3).encode("utf-8")

    parser = ESP32FrameParser()
    results = parser.feed(combined_chunk)

    assert len(results) == 3
    assert all(r.is_success for r in results)
    assert [r.frame.sequence for r in results] == [10, 11, 12]
    assert parser.stats["valid_frames"] == 3


def test_crlf_and_lf_line_endings():
    """Verify parser transparently accepts CRLF and LF lines and skips empty lines."""
    now = time.time()
    source = SyntheticESP32Source()
    f1 = source.make_frame(port=1, voltage_v=5.0, current_a=0.2, timestamp=now, device_id="dev-1")
    f2 = source.make_frame(port=1, voltage_v=5.0, current_a=0.2, timestamp=now, device_id="dev-1")

    # Replace \n with \r\n and insert empty blank lines
    stream = f1.replace("\n", "\r\n") + "\r\n\n\r\n" + f2

    parser = ESP32FrameParser()
    results = parser.feed(stream.encode("utf-8"))

    assert len(results) == 2
    assert all(r.is_success for r in results)


def test_corrupt_crc_rejected():
    """Verify corrupt CRC-32 (simulating UART transmission noise) is rejected."""
    now = time.time()
    source = SyntheticESP32Source()
    corrupt_frame = source.make_frame(
        port=1,
        voltage_v=5.0,
        current_a=0.2,
        timestamp=now,
        device_id="dev-1",
        corrupt_crc=True,
    )

    parser = ESP32FrameParser(require_crc=True)
    results = parser.feed(corrupt_frame.encode("utf-8"))

    assert len(results) == 1
    res = results[0]
    assert not res.is_success
    assert res.error is not None
    assert res.error.reason == FrameErrorReason.CRC_MISMATCH
    assert "CRC-32 checksum mismatch" in res.error.message
    assert parser.stats["corrupt_frames"] == 1


def test_crc_disabled_mode():
    """Verify parser accepts frames without CRC when require_crc is False."""
    now = time.time()
    source = SyntheticESP32Source()
    no_crc_frame = source.make_frame(
        port=1,
        voltage_v=5.0,
        current_a=0.2,
        timestamp=now,
        device_id="dev-1",
        include_crc=False,
    )

    parser = ESP32FrameParser(require_crc=False)
    results = parser.feed(no_crc_frame.encode("utf-8"))

    assert len(results) == 1
    assert results[0].is_success
    assert results[0].frame.crc32 is None


def test_malformed_json_rejected():
    """Verify malformed JSON syntax is rejected with MALFORMED_JSON."""
    parser = ESP32FrameParser()
    results = parser.feed(b'{"v": 1, "seq": 1, "port": 1, INVALID_JSON\n')

    assert len(results) == 1
    res = results[0]
    assert not res.is_success
    assert res.error.reason == FrameErrorReason.MALFORMED_JSON


def test_unsupported_version_rejected():
    """Verify protocol version != 1 is rejected."""
    now = time.time()
    source = SyntheticESP32Source()
    bad_ver_frame = source.make_frame(
        port=1,
        voltage_v=5.0,
        current_a=0.2,
        timestamp=now,
        device_id="dev-1",
        version=99,
    )

    parser = ESP32FrameParser()
    results = parser.feed(bad_ver_frame.encode("utf-8"))

    assert len(results) == 1
    res = results[0]
    assert not res.is_success
    assert res.error.reason == FrameErrorReason.UNSUPPORTED_VERSION


def test_missing_required_fields_rejected():
    """Verify missing required fields (voltage_v, current_a, timestamp, etc.) are rejected."""
    parser = ESP32FrameParser(require_crc=False)

    # Missing current_a
    payload = {"v": 1, "seq": 1, "port": 1, "voltage_v": 5.0, "timestamp": time.time(), "device_id": "dev-1"}
    line = json.dumps(payload) + "\n"

    results = parser.feed(line.encode("utf-8"))
    assert len(results) == 1
    assert results[0].error.reason == FrameErrorReason.MISSING_FIELD
    assert "current_a" in results[0].error.message


def test_invalid_field_types_rejected():
    """Verify boolean or string types passed for numeric fields are rejected."""
    parser = ESP32FrameParser(require_crc=False)

    # Boolean passed as voltage_v
    payload = {"v": 1, "seq": 1, "port": 1, "voltage_v": True, "current_a": 0.5, "timestamp": time.time(), "device_id": "dev-1"}
    line = json.dumps(payload) + "\n"

    results = parser.feed(line.encode("utf-8"))
    assert len(results) == 1
    assert results[0].error.reason == FrameErrorReason.INVALID_FIELD_TYPE


def test_nan_and_inf_rejected():
    """Verify NaN and Infinity in sensor measurements are rejected."""
    parser = ESP32FrameParser(require_crc=False)

    # Use raw string since json.loads standard doesn't write NaN unless formatted
    line = '{"v": 1, "seq": 1, "port": 1, "voltage_v": NaN, "current_a": 0.5, "timestamp": 1700000000.0, "device_id": "dev-1"}\n'
    results = parser.feed(line.encode("utf-8"))

    assert len(results) == 1
    assert results[0].error.reason == FrameErrorReason.NON_FINITE_VALUE
    assert "finite number" in results[0].error.message


def test_negative_timestamp_rejected():
    """Verify negative timestamp is rejected."""
    parser = ESP32FrameParser(require_crc=False)
    payload = {"v": 1, "seq": 1, "port": 1, "voltage_v": 5.0, "current_a": 0.5, "timestamp": -100.0, "device_id": "dev-1"}
    line = json.dumps(payload) + "\n"

    results = parser.feed(line.encode("utf-8"))
    assert len(results) == 1
    assert results[0].error.reason == FrameErrorReason.NEGATIVE_TIMESTAMP


def test_sequence_tracking_and_regression_detection():
    """Verify sequence regression triggers OUT_OF_SEQUENCE error."""
    now = time.time()
    source = SyntheticESP32Source(start_seq=50)
    f1 = source.make_frame(port=1, seq=50, timestamp=now, device_id="dev-1")
    f2 = source.make_frame(port=1, seq=51, timestamp=now, device_id="dev-1")
    # Duplicate sequence 51
    f_dup = source.make_frame(port=1, seq=51, timestamp=now, device_id="dev-1")
    # Regressed sequence 49
    f_regress = source.make_frame(port=1, seq=49, timestamp=now, device_id="dev-1")

    parser = ESP32FrameParser()
    r1 = parser.feed(f1)[0]
    r2 = parser.feed(f2)[0]
    r_dup = parser.feed(f_dup)[0]
    r_reg = parser.feed(f_regress)[0]

    assert r1.is_success
    assert r2.is_success
    assert not r_dup.is_success
    assert r_dup.error.reason == FrameErrorReason.OUT_OF_SEQUENCE
    assert not r_reg.is_success
    assert r_reg.error.reason == FrameErrorReason.OUT_OF_SEQUENCE


def test_sequence_reset_on_reboot():
    """Verify reset_sequence allows new starting sequence counter."""
    now = time.time()
    source = SyntheticESP32Source()
    f1 = source.make_frame(port=1, seq=100, timestamp=now, device_id="dev-1")
    f_reboot = source.make_frame(port=1, seq=1, timestamp=now, device_id="dev-1")

    parser = ESP32FrameParser()
    assert parser.feed(f1)[0].is_success

    # Without reset, seq=1 fails
    assert not parser.feed(f_reboot)[0].is_success

    # Reset sequence tracker (simulating acknowledged MCU reboot)
    parser.reset_sequence(port=1)
    res_after_reset = parser.feed(f_reboot)[0]
    assert res_after_reset.is_success


def test_buffer_overflow_runaway_line():
    """Verify buffer overflow protection discards oversized data without crashing."""
    parser = ESP32FrameParser(max_frame_bytes=200)

    # Feed 250 bytes without newline
    oversized_junk = b"X" * 250
    results1 = parser.feed(oversized_junk)

    assert len(results1) == 1
    assert results1[0].error.reason == FrameErrorReason.BUFFER_OVERFLOW

    # Now feed a valid frame (~140 bytes <= 200) and verify parser recovers
    now = time.time()
    source = SyntheticESP32Source()
    valid_frame = source.make_frame(port=1, voltage_v=5.0, current_a=0.2, timestamp=now, device_id="dev-1")

    results2 = parser.feed(valid_frame.encode("utf-8"))
    assert len(results2) == 1
    assert results2[0].is_success


def test_device_resolution_via_registry():
    """Verify device ID is automatically resolved from DeviceRegistry by port."""
    registry = DeviceRegistry()
    registry.register(Device(device_id="dock-registered-dev", mac_address="00:11:22:33:44:55", physical_port=2))

    now = time.time()
    source = SyntheticESP32Source()
    # Frame does NOT specify device_id
    frame_no_dev = source.make_frame(port=2, voltage_v=5.0, current_a=0.3, timestamp=now, device_id=None)

    parser = ESP32FrameParser(registry=registry)
    results = parser.feed(frame_no_dev.encode("utf-8"))

    assert len(results) == 1
    assert results[0].is_success
    assert results[0].telemetry.device_id == "dock-registered-dev"


def test_device_resolution_via_port_map():
    """Verify device ID is resolved from static port_device_map."""
    now = time.time()
    source = SyntheticESP32Source()
    frame_no_dev = source.make_frame(port=3, voltage_v=5.0, current_a=0.3, timestamp=now, device_id=None)

    parser = ESP32FrameParser(port_device_map={3: "mapped-dev-03"})
    results = parser.feed(frame_no_dev.encode("utf-8"))

    assert len(results) == 1
    assert results[0].is_success
    assert results[0].telemetry.device_id == "mapped-dev-03"


def test_unmapped_port_triggers_error():
    """Verify frame without device_id on unknown port triggers UNMAPPED_PORT."""
    now = time.time()
    source = SyntheticESP32Source()
    frame_no_dev = source.make_frame(port=9, voltage_v=5.0, current_a=0.3, timestamp=now, device_id=None)

    parser = ESP32FrameParser()
    results = parser.feed(frame_no_dev.encode("utf-8"))

    assert len(results) == 1
    assert not results[0].is_success
    assert results[0].error.reason == FrameErrorReason.UNMAPPED_PORT


def test_physical_bounds_violation_surfaced():
    """Verify overvoltage or overcurrent triggers VALIDATION_FAILED."""
    now = time.time()
    source = SyntheticESP32Source()
    # 35V is well above the default max of 24V
    overvoltage_frame = source.make_frame(port=1, voltage_v=35.0, current_a=0.5, timestamp=now, device_id="dev-1")

    parser = ESP32FrameParser()
    results = parser.feed(overvoltage_frame.encode("utf-8"))

    assert len(results) == 1
    assert not results[0].is_success
    assert results[0].error.reason == FrameErrorReason.VALIDATION_FAILED
    assert "out of bounds" in results[0].error.message


def test_audit_logging_on_frame_errors():
    """Verify corrupt frames generate structured audit events when AuditLog is passed."""
    audit_log = AuditLog()
    now = time.time()
    source = SyntheticESP32Source()
    corrupt_frame = source.make_frame(port=1, voltage_v=5.0, current_a=0.2, timestamp=now, device_id="dev-1", corrupt_crc=True)

    parser = ESP32FrameParser(audit_log=audit_log)
    parser.feed(corrupt_frame.encode("utf-8"))

    events = audit_log.get_events()
    assert len(events) == 1
    assert events[0].event_type == AuditEventType.TELEMETRY_INVALID
    assert events[0].reason_code == "ESP32_TRANSPORT_CRC_MISMATCH"
    assert "CRC-32 checksum mismatch" in events[0].details["message"]
