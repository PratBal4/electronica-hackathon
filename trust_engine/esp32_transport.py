"""ESP32 Serial Transport, Frame Parser, and Ingestion Pipeline.

Parses line-delimited telemetry frames streamed from an ESP32 microcontroller
measuring physical port characteristics via an INA3221 voltage/current monitor.

Enforces protocol versioning, CRC-32 integrity validation (UART transmission noise
rejection), stream buffer chunking/reassembly, sequence monotonicity tracking,
and physical bounds verification.
"""

from dataclasses import dataclass, field
from enum import Enum
import json
import logging
import math
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import zlib

from trust_engine.audit import AuditEvent, AuditEventType, AuditLog
from trust_engine.device import Device
from trust_engine.registry import DeviceRegistry
from trust_engine.telemetry import (
    PhysicalBoundsConfig,
    PhysicalTelemetry,
    TelemetryValidationError,
    TelemetryValidator,
    validate_physical_telemetry,
)

logger = logging.getLogger(__name__)

# Protocol constants
CURRENT_PROTOCOL_VERSION = 1
DEFAULT_MAX_FRAME_BYTES = 1024


class FrameErrorReason(Enum):
    """Categorized root causes of ESP32 transport or frame parsing failures."""

    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    DECODE_ERROR = "DECODE_ERROR"
    MALFORMED_JSON = "MALFORMED_JSON"
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    MISSING_FIELD = "MISSING_FIELD"
    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    NON_FINITE_VALUE = "NON_FINITE_VALUE"
    NEGATIVE_TIMESTAMP = "NEGATIVE_TIMESTAMP"
    CRC_MISMATCH = "CRC_MISMATCH"
    OUT_OF_SEQUENCE = "OUT_OF_SEQUENCE"
    UNMAPPED_PORT = "UNMAPPED_PORT"
    VALIDATION_FAILED = "VALIDATION_FAILED"


@dataclass(frozen=True)
class ESP32Frame:
    """Parsed, structured envelope of an ESP32 sensor report.

    Attributes:
        version: Protocol version integer (must equal CURRENT_PROTOCOL_VERSION).
        sequence: Monotonically increasing sequence number from ESP32.
        port: Physical dock port monitored by INA3221 (e.g. 1, 2, 3).
        voltage_v: Measured bus voltage in Volts.
        current_a: Measured shunt current in Amperes.
        timestamp: POSIX epoch timestamp in seconds.
        temperature_c: Optional ambient/shunt temperature in Celsius.
        device_id: Optional docked device identifier reported or associated.
        crc32: CRC-32 checksum string over canonical frame payload.
    """

    version: int
    sequence: int
    port: Union[int, str]
    voltage_v: float
    current_a: float
    timestamp: float
    temperature_c: Optional[float] = None
    device_id: Optional[str] = None
    crc32: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert frame to dictionary."""
        d: Dict[str, Any] = {
            "v": self.version,
            "seq": self.sequence,
            "port": self.port,
            "voltage_v": self.voltage_v,
            "current_a": self.current_a,
            "timestamp": self.timestamp,
        }
        if self.temperature_c is not None:
            d["temp_c"] = self.temperature_c
        if self.device_id is not None:
            d["device_id"] = self.device_id
        if self.crc32 is not None:
            d["crc32"] = self.crc32
        return d


@dataclass(frozen=True)
class FrameParseError:
    """Detailed metadata for a rejected or corrupt frame."""

    reason: FrameErrorReason
    message: str
    raw_data: Optional[str] = None
    sequence: Optional[int] = None
    port: Optional[Union[int, str]] = None


@dataclass
class FrameParseResult:
    """Outcome of attempting to parse a frame line from the transport stream."""

    frame: Optional[ESP32Frame] = None
    telemetry: Optional[PhysicalTelemetry] = None
    error: Optional[FrameParseError] = None

    @property
    def is_success(self) -> bool:
        """True if the frame was parsed and converted to valid telemetry."""
        return self.telemetry is not None and self.error is None


def compute_frame_crc32(payload: Dict[str, Any]) -> str:
    """Calculate deterministic CRC-32 hex digest over a frame payload.

    Excludes the 'crc32' field itself. Serializes keys deterministically
    using sorted keys and compact separators without whitespace.

    Args:
        payload: Dictionary containing frame fields.

    Returns:
        8-character lowercase hexadecimal CRC-32 string (e.g. '3a1f8b2c').
    """
    clean_dict = {k: v for k, v in payload.items() if k != "crc32"}
    canonical_json = json.dumps(clean_dict, sort_keys=True, separators=(",", ":"))
    crc_int = zlib.crc32(canonical_json.encode("utf-8"))
    return f"{crc_int:08x}"


def format_esp32_frame(frame: ESP32Frame, include_crc: bool = True) -> str:
    """Format an ESP32Frame as a newline-terminated JSON string.

    Args:
        frame: The ESP32Frame to serialize.
        include_crc: If True, computes and includes the 'crc32' envelope field.

    Returns:
        Newline-terminated JSON string ready for serial transmission.
    """
    data = frame.to_dict()
    if "crc32" in data:
        del data["crc32"]

    if include_crc:
        data["crc32"] = compute_frame_crc32(data)

    return json.dumps(data, separators=(",", ":")) + "\n"


class ESP32FrameParser:
    """Stream parser and telemetry ingestion pipeline for ESP32 UART telemetry.

    Features:
    - In-memory stream buffer re-assembly handling arbitrary chunk slicing.
    - Buffer overflow / runaway line protection against missing newlines.
    - CRC-32 transmission noise verification.
    - Sequence number regression tracking.
    - Automatic port-to-device mapping via static map or DeviceRegistry.
    - Telemetry schema, bounds, and freshness verification via TelemetryValidator.
    - Audit logging of frame rejections and transmission anomalies.
    """

    def __init__(
        self,
        max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
        require_crc: bool = True,
        track_sequence: bool = True,
        bounds_config: Optional[PhysicalBoundsConfig] = None,
        validator: Optional[TelemetryValidator] = None,
        port_device_map: Optional[Dict[Union[int, str], str]] = None,
        registry: Optional[DeviceRegistry] = None,
        audit_log: Optional[AuditLog] = None,
    ) -> None:
        self.max_frame_bytes = max_frame_bytes
        self.require_crc = require_crc
        self.track_sequence = track_sequence
        self.bounds_config = bounds_config or PhysicalBoundsConfig()
        self.validator = validator or TelemetryValidator(physical_bounds=self.bounds_config)
        self.port_device_map = dict(port_device_map or {})
        self.registry = registry
        self.audit_log = audit_log

        # State tracking
        self._buffer = bytearray()
        self._last_sequence_by_port: Dict[Union[int, str], int] = {}
        self._total_frames_received: int = 0
        self._valid_frames_count: int = 0
        self._corrupt_frames_count: int = 0

    @property
    def stats(self) -> Dict[str, Any]:
        """Current parser operational statistics."""
        return {
            "total_frames_received": self._total_frames_received,
            "valid_frames": self._valid_frames_count,
            "corrupt_frames": self._corrupt_frames_count,
            "buffer_size_bytes": len(self._buffer),
            "tracked_ports": list(self._last_sequence_by_port.keys()),
        }

    def reset_buffer(self) -> None:
        """Discard in-memory stream buffer."""
        self._buffer.clear()

    def reset_sequence(self, port: Optional[Union[int, str]] = None) -> None:
        """Reset sequence tracker for a specific port or all ports."""
        if port is not None:
            self._last_sequence_by_port.pop(port, None)
        else:
            self._last_sequence_by_port.clear()

    def feed(self, chunk: Union[bytes, str]) -> List[FrameParseResult]:
        """Feed a stream chunk (bytes or str) into the parser buffer.

        Extracts and parses all complete lines delimited by newline (LF / CRLF).

        Args:
            chunk: Raw bytes or string chunk received from serial/transport.

        Returns:
            List of FrameParseResult for every completed line in the stream.
        """
        if isinstance(chunk, str):
            raw_bytes = chunk.encode("utf-8")
        elif isinstance(chunk, (bytes, bytearray)):
            raw_bytes = bytes(chunk)
        else:
            raise TypeError(f"Expected bytes or str chunk, got {type(chunk).__name__}")

        self._buffer.extend(raw_bytes)
        results: List[FrameParseResult] = []

        while True:
            # Check for buffer overflow if no newline exists in oversized buffer
            newline_pos = self._buffer.find(b"\n")

            if newline_pos == -1:
                if len(self._buffer) > self.max_frame_bytes:
                    # Buffer exceeded limit without a delimiter: discard and log error
                    discarded_len = len(self._buffer)
                    self._buffer.clear()
                    self._corrupt_frames_count += 1
                    err = FrameParseError(
                        reason=FrameErrorReason.BUFFER_OVERFLOW,
                        message=f"Frame buffer exceeded {self.max_frame_bytes} bytes without newline; discarded {discarded_len} bytes",
                    )
                    self._record_audit_error(err)
                    results.append(FrameParseResult(error=err))
                break

            # If newline is found beyond max_frame_bytes, line was runaway
            if newline_pos > self.max_frame_bytes:
                line_bytes = bytes(self._buffer[:newline_pos])
                del self._buffer[: newline_pos + 1]
                self._corrupt_frames_count += 1
                err = FrameParseError(
                    reason=FrameErrorReason.BUFFER_OVERFLOW,
                    message=f"Line length ({len(line_bytes)} bytes) exceeded maximum ({self.max_frame_bytes} bytes)",
                    raw_data=line_bytes[:64].decode("utf-8", errors="replace") + "...",
                )
                self._record_audit_error(err)
                results.append(FrameParseResult(error=err))
                continue

            # Extract line up to newline
            line_bytes = bytes(self._buffer[:newline_pos])
            del self._buffer[: newline_pos + 1]

            # Strip carriage return if CRLF
            if line_bytes.endswith(b"\r"):
                line_bytes = line_bytes[:-1]

            # Empty lines (extra newlines) are skipped silently
            if not line_bytes.strip():
                continue

            # Attempt UTF-8 decoding
            try:
                line_str = line_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                self._corrupt_frames_count += 1
                err = FrameParseError(
                    reason=FrameErrorReason.DECODE_ERROR,
                    message=f"UTF-8 decode failed: {exc}",
                    raw_data=line_bytes[:64].hex(),
                )
                self._record_audit_error(err)
                results.append(FrameParseResult(error=err))
                continue

            res = self.parse_line(line_str)
            results.append(res)

        return results

    def parse_line(self, line: str) -> FrameParseResult:
        """Parse, verify, and validate a single raw line string.

        Args:
            line: A complete line string without trailing newlines.

        Returns:
            FrameParseResult with either valid telemetry or structured error.
        """
        self._total_frames_received += 1

        # 1. JSON parsing
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.MALFORMED_JSON,
                message=f"JSON parsing error: {exc.msg} at line {exc.lineno} col {exc.colno}",
                raw_data=line[:128],
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        if not isinstance(payload, dict):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.MALFORMED_JSON,
                message=f"Top-level payload must be a JSON object, got {type(payload).__name__}",
                raw_data=line[:128],
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        # 2. Protocol version check
        version = payload.get("v")
        if version is None:
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.MISSING_FIELD,
                message="Missing required protocol version field 'v'",
                raw_data=line[:128],
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        if not isinstance(version, int) or isinstance(version, bool):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.INVALID_FIELD_TYPE,
                message=f"Protocol version 'v' must be an integer, got {type(version).__name__}",
                raw_data=line[:128],
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        if version != CURRENT_PROTOCOL_VERSION:
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.UNSUPPORTED_VERSION,
                message=f"Unsupported protocol version {version} (expected {CURRENT_PROTOCOL_VERSION})",
                raw_data=line[:128],
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        # 3. Required fields check
        required_fields = ["seq", "port", "voltage_v", "current_a", "timestamp"]
        for rf in required_fields:
            if rf not in payload:
                self._corrupt_frames_count += 1
                err = FrameParseError(
                    reason=FrameErrorReason.MISSING_FIELD,
                    message=f"Missing required field '{rf}' in telemetry frame",
                    raw_data=line[:128],
                )
                self._record_audit_error(err)
                return FrameParseResult(error=err)

        # 4. CRC-32 verification
        frame_crc = payload.get("crc32")
        if self.require_crc:
            if not frame_crc:
                self._corrupt_frames_count += 1
                err = FrameParseError(
                    reason=FrameErrorReason.MISSING_FIELD,
                    message="Missing required 'crc32' integrity checksum",
                    raw_data=line[:128],
                )
                self._record_audit_error(err)
                return FrameParseResult(error=err)

            expected_crc = compute_frame_crc32(payload)
            if str(frame_crc).strip().lower() != expected_crc:
                self._corrupt_frames_count += 1
                err = FrameParseError(
                    reason=FrameErrorReason.CRC_MISMATCH,
                    message=f"CRC-32 checksum mismatch: received '{frame_crc}', expected '{expected_crc}'",
                    raw_data=line[:128],
                    sequence=payload.get("seq") if isinstance(payload.get("seq"), int) else None,
                    port=payload.get("port"),
                )
                self._record_audit_error(err)
                return FrameParseResult(error=err)

        # 5. Type and numeric sanity validation
        seq = payload["seq"]
        if not isinstance(seq, int) or isinstance(seq, bool):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.INVALID_FIELD_TYPE,
                message=f"Sequence 'seq' must be an integer, got {type(seq).__name__}",
                raw_data=line[:128],
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        port = payload["port"]
        if not isinstance(port, (int, str)) or isinstance(port, bool):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.INVALID_FIELD_TYPE,
                message=f"Port 'port' must be int or str, got {type(port).__name__}",
                raw_data=line[:128],
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        voltage_v = payload["voltage_v"]
        if not isinstance(voltage_v, (int, float)) or isinstance(voltage_v, bool):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.INVALID_FIELD_TYPE,
                message=f"voltage_v must be numeric, got {type(voltage_v).__name__}",
                raw_data=line[:128],
                sequence=seq,
                port=port,
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        if not math.isfinite(voltage_v):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.NON_FINITE_VALUE,
                message=f"voltage_v must be a finite number, got {voltage_v}",
                raw_data=line[:128],
                sequence=seq,
                port=port,
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        current_a = payload["current_a"]
        if not isinstance(current_a, (int, float)) or isinstance(current_a, bool):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.INVALID_FIELD_TYPE,
                message=f"current_a must be numeric, got {type(current_a).__name__}",
                raw_data=line[:128],
                sequence=seq,
                port=port,
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        if not math.isfinite(current_a):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.NON_FINITE_VALUE,
                message=f"current_a must be a finite number, got {current_a}",
                raw_data=line[:128],
                sequence=seq,
                port=port,
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        timestamp = payload["timestamp"]
        if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.INVALID_FIELD_TYPE,
                message=f"timestamp must be numeric, got {type(timestamp).__name__}",
                raw_data=line[:128],
                sequence=seq,
                port=port,
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        if not math.isfinite(timestamp):
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.NON_FINITE_VALUE,
                message=f"timestamp must be finite, got {timestamp}",
                raw_data=line[:128],
                sequence=seq,
                port=port,
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        if timestamp < 0:
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.NEGATIVE_TIMESTAMP,
                message=f"timestamp cannot be negative, got {timestamp}",
                raw_data=line[:128],
                sequence=seq,
                port=port,
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        temp_c = payload.get("temp_c")
        if temp_c is not None:
            if not isinstance(temp_c, (int, float)) or isinstance(temp_c, bool):
                self._corrupt_frames_count += 1
                err = FrameParseError(
                    reason=FrameErrorReason.INVALID_FIELD_TYPE,
                    message=f"temp_c must be numeric if provided, got {type(temp_c).__name__}",
                    raw_data=line[:128],
                    sequence=seq,
                    port=port,
                )
                self._record_audit_error(err)
                return FrameParseResult(error=err)
            if not math.isfinite(temp_c):
                self._corrupt_frames_count += 1
                err = FrameParseError(
                    reason=FrameErrorReason.NON_FINITE_VALUE,
                    message=f"temp_c must be finite, got {temp_c}",
                    raw_data=line[:128],
                    sequence=seq,
                    port=port,
                )
                self._record_audit_error(err)
                return FrameParseResult(error=err)
            temp_c = float(temp_c)

        # 6. Monotonic sequence check per port
        if self.track_sequence:
            last_seq = self._last_sequence_by_port.get(port)
            if last_seq is not None and seq <= last_seq:
                self._corrupt_frames_count += 1
                err = FrameParseError(
                    reason=FrameErrorReason.OUT_OF_SEQUENCE,
                    message=f"Sequence regression on port {port}: received {seq} <= last seen {last_seq}",
                    raw_data=line[:128],
                    sequence=seq,
                    port=port,
                )
                self._record_audit_error(err)
                return FrameParseResult(error=err)
            self._last_sequence_by_port[port] = seq

        # 7. Device resolution
        device_id = payload.get("device_id")
        if device_id:
            device_id = str(device_id).strip()
        else:
            device_id = self._resolve_device_id_for_port(port)

        if not device_id:
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.UNMAPPED_PORT,
                message=f"No device registered or mapped for physical port '{port}'",
                raw_data=line[:128],
                sequence=seq,
                port=port,
            )
            self._record_audit_error(err)
            return FrameParseResult(error=err)

        # 8. Create ESP32Frame object
        frame_obj = ESP32Frame(
            version=version,
            sequence=seq,
            port=port,
            voltage_v=float(voltage_v),
            current_a=float(current_a),
            timestamp=float(timestamp),
            temperature_c=temp_c,
            device_id=device_id,
            crc32=str(frame_crc).strip().lower() if frame_crc else None,
        )

        # 9. Create PhysicalTelemetry and validate bounds/freshness
        telemetry = PhysicalTelemetry(
            device_id=device_id,
            physical_port=port,
            voltage_v=float(voltage_v),
            current_a=float(current_a),
            timestamp=float(timestamp),
            temperature_c=temp_c,
        )

        val_result = self.validator.validate_physical(telemetry)
        if not val_result.is_valid:
            self._corrupt_frames_count += 1
            err = FrameParseError(
                reason=FrameErrorReason.VALIDATION_FAILED,
                message=f"Physical telemetry bounds validation failed: {'; '.join(val_result.errors)}",
                raw_data=line[:128],
                sequence=seq,
                port=port,
            )
            self._record_audit_error(err)
            return FrameParseResult(frame=frame_obj, error=err)

        # Success!
        self._valid_frames_count += 1
        return FrameParseResult(frame=frame_obj, telemetry=telemetry)

    def _resolve_device_id_for_port(self, port: Union[int, str]) -> Optional[str]:
        """Resolve device ID for physical port via map or DeviceRegistry."""
        # Check explicit port_device_map
        if port in self.port_device_map:
            return self.port_device_map[port]
        str_port = str(port)
        if str_port in self.port_device_map:
            return self.port_device_map[str_port]

        # Check DeviceRegistry
        if self.registry:
            for dev in self.registry.list_devices():
                if str(dev.physical_port) == str_port:
                    return dev.device_id

        return None

    def _record_audit_error(self, err: FrameParseError) -> None:
        """Record parser error to AuditLog if configured."""
        if self.audit_log is None:
            return

        self.audit_log.record(
            event_type=AuditEventType.TELEMETRY_INVALID,
            device_id=None,
            reason_code=f"ESP32_TRANSPORT_{err.reason.value}",
            details={
                "message": err.message,
                "sequence": err.sequence,
                "port": str(err.port) if err.port is not None else None,
                "raw_snippet": err.raw_data,
            },
        )


class SyntheticESP32Source:
    """Deterministic synthetic telemetry stream generator for test and simulation.

    Generates realistic ESP32 telemetry frames and streams, supporting arbitrary
    byte slicing, CRC corruption, electrical spikes, clock skew, and runaway buffers.
    """

    def __init__(self, start_seq: int = 1) -> None:
        self.seq_counter = start_seq

    def make_frame(
        self,
        port: Union[int, str] = 1,
        voltage_v: float = 5.05,
        current_a: float = 0.45,
        temp_c: Optional[float] = 36.5,
        timestamp: Optional[float] = None,
        device_id: Optional[str] = "dock-dev-01",
        seq: Optional[int] = None,
        version: int = CURRENT_PROTOCOL_VERSION,
        include_crc: bool = True,
        corrupt_crc: bool = False,
    ) -> str:
        """Create a single formatted newline-terminated JSON telemetry frame string.

        Args:
            port: Dock port number.
            voltage_v: INA3221 bus voltage in Volts.
            current_a: INA3221 shunt current in Amperes.
            temp_c: Optional temperature in Celsius.
            timestamp: Epoch seconds (defaults to current time).
            device_id: Associated device ID.
            seq: Explicit sequence counter (increments internal counter if None).
            version: Protocol version.
            include_crc: Whether to compute CRC-32.
            corrupt_crc: If True, intentionally corrupts CRC-32 to simulate line noise.

        Returns:
            Formatted newline-terminated JSON frame string.
        """
        if seq is None:
            seq = self.seq_counter
            self.seq_counter += 1

        if timestamp is None:
            timestamp = time.time()

        payload: Dict[str, Any] = {
            "v": version,
            "seq": seq,
            "port": port,
            "voltage_v": voltage_v,
            "current_a": current_a,
            "timestamp": timestamp,
        }
        if temp_c is not None:
            payload["temp_c"] = temp_c
        if device_id is not None:
            payload["device_id"] = device_id

        if include_crc:
            crc = compute_frame_crc32(payload)
            if corrupt_crc:
                # Invert last characters to corrupt
                crc = crc[:-2] + "ff" if not crc.endswith("ff") else crc[:-2] + "00"
            payload["crc32"] = crc

        return json.dumps(payload, separators=(",", ":")) + "\n"

    def make_chunked_stream(self, frame_str: str, chunk_size: int = 7) -> List[bytes]:
        """Split a frame string into arbitrary byte chunks to test stream buffering.

        Args:
            frame_str: Frame string to split.
            chunk_size: Byte chunk size (default: 7 bytes).

        Returns:
            List of raw byte chunks.
        """
        raw = frame_str.encode("utf-8")
        return [raw[i : i + chunk_size] for i in range(0, len(raw), chunk_size)]
