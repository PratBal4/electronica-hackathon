"""Telemetry models and validation for the Smart Backplane Trust Engine.

Defines schemas for physical sensor readings (e.g. INA3221 voltage/current)
and network metadata observations. Implements deterministic schema, type,
freshness, finite numeric, and configurable range validation.

Honest Scope:
    Telemetry constitutes observable evidence, NEVER proof of identity.
    A device exhibiting compliant power consumption or standard network
    traffic is NOT proven to be authentic or uncompromised.
"""

from dataclasses import dataclass, field
import logging
import math
import time
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class TelemetryValidationError(ValueError):
    """Raised when telemetry fails schema, type, bounds, or freshness validation."""


@dataclass(frozen=True)
class PhysicalBoundsConfig:
    """Configurable boundaries and freshness limits for physical telemetry."""

    min_voltage_v: float = 0.0
    max_voltage_v: float = 24.0
    min_current_a: float = 0.0
    max_current_a: float = 5.0
    min_temperature_c: float = -40.0
    max_temperature_c: float = 125.0
    max_age_seconds: float = 60.0
    max_future_skew_seconds: float = 5.0


@dataclass(frozen=True)
class NetworkBoundsConfig:
    """Configurable boundaries and freshness limits for network telemetry."""

    min_packet_count: int = 0
    max_packet_count: int = 1_000_000_000
    min_byte_count: int = 0
    max_byte_count: int = 100_000_000_000
    max_age_seconds: float = 60.0
    max_future_skew_seconds: float = 5.0
    min_port: int = 1
    max_port: int = 65535


@dataclass
class ValidationResult:
    """Structured result of a telemetry validation check."""

    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def raise_if_invalid(self) -> None:
        """Raise TelemetryValidationError if validation failed."""
        if not self.is_valid:
            error_details = "; ".join(self.errors)
            raise TelemetryValidationError(f"Telemetry validation failed: {error_details}")


@dataclass
class PhysicalTelemetry:
    """Physical telemetry record observed for a dock port and associated device.

    All units are explicit in attribute names:
        voltage_v: Volts (V)
        current_a: Amperes (A)
        temperature_c: Degrees Celsius (°C)
        timestamp: POSIX timestamp in seconds
    """

    device_id: str
    physical_port: Union[int, str]
    voltage_v: float
    current_a: float
    timestamp: float
    temperature_c: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary representation."""
        return {
            "device_id": self.device_id,
            "physical_port": self.physical_port,
            "voltage_v": self.voltage_v,
            "current_a": self.current_a,
            "timestamp": self.timestamp,
            "temperature_c": self.temperature_c,
        }


@dataclass
class NetworkTelemetry:
    """Network telemetry record observed for traffic associated with a device.

    Attributes:
        source_mac: Observed source MAC address.
        source_ip: Observed source IP address.
        destination: Destination IP, hostname, or network endpoint.
        protocol: Network transport protocol (e.g. 'TCP', 'UDP', 'ICMP').
        packet_count: Non-negative packet count observed in sample.
        byte_count: Non-negative byte count observed in sample.
        timestamp: POSIX timestamp in seconds.
        device_id: Optional association with known device ID.
        physical_port: Optional physical dock port where traffic was observed.
        source_port: Optional source transport port (1-65535).
        destination_port: Optional destination transport port (1-65535).
        window_duration_s: Optional duration of observation window in seconds.
    """

    source_mac: str
    source_ip: str
    destination: str
    protocol: str
    packet_count: int
    byte_count: int
    timestamp: float
    device_id: Optional[str] = None
    physical_port: Optional[Union[int, str]] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    window_duration_s: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to dictionary representation."""
        return {
            "source_mac": self.source_mac,
            "source_ip": self.source_ip,
            "destination": self.destination,
            "protocol": self.protocol,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "timestamp": self.timestamp,
            "device_id": self.device_id,
            "physical_port": self.physical_port,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "window_duration_s": self.window_duration_s,
        }


class TelemetryValidator:
    """Validates physical and network telemetry against schemas, types, and bounds.

    Validation is strictly decoupled from policy decisions: a telemetry record
    that passes validation is confirmed to be syntactically well-formed, finite,
    and fresh; policy rules subsequently evaluate whether those readings satisfy
    admission or operational criteria.
    """

    def __init__(
        self,
        physical_bounds: Optional[PhysicalBoundsConfig] = None,
        network_bounds: Optional[NetworkBoundsConfig] = None,
    ) -> None:
        """Initialize validator with configurable bounds."""
        self.physical_bounds = physical_bounds or PhysicalBoundsConfig()
        self.network_bounds = network_bounds or NetworkBoundsConfig()

    def validate_physical(
        self,
        telemetry: Any,
        current_time: Optional[float] = None,
    ) -> ValidationResult:
        """Validate physical telemetry record.

        Args:
            telemetry: The PhysicalTelemetry instance to validate.
            current_time: Reference time for freshness check (defaults to time.time()).

        Returns:
            ValidationResult containing is_valid status and any errors.
        """
        errors: List[str] = []
        bounds = self.physical_bounds
        ref_time = current_time if current_time is not None else time.time()

        if not isinstance(telemetry, PhysicalTelemetry):
            errors.append(f"Expected PhysicalTelemetry instance, got {type(telemetry).__name__}")
            return ValidationResult(is_valid=False, errors=errors)

        # 1. Device ID validation
        if not isinstance(telemetry.device_id, str) or not telemetry.device_id.strip():
            errors.append("device_id must be a non-empty string")

        # 2. Physical Port validation
        if isinstance(telemetry.physical_port, bool):
            errors.append("physical_port must be int or str, got bool")
        elif isinstance(telemetry.physical_port, str):
            if not telemetry.physical_port.strip():
                errors.append("physical_port as string must not be empty")
        elif not isinstance(telemetry.physical_port, int):
            errors.append(
                f"physical_port must be int or non-empty str, got {type(telemetry.physical_port).__name__}"
            )

        # 3. Voltage validation (finite, bounds)
        if isinstance(telemetry.voltage_v, bool) or not isinstance(telemetry.voltage_v, (int, float)):
            errors.append(f"voltage_v must be numeric, got {type(telemetry.voltage_v).__name__}")
        elif not math.isfinite(telemetry.voltage_v):
            errors.append(f"voltage_v must be a finite number; got {telemetry.voltage_v}")
        else:
            v = float(telemetry.voltage_v)
            if v < bounds.min_voltage_v or v > bounds.max_voltage_v:
                errors.append(
                    f"voltage_v {v} V out of bounds [{bounds.min_voltage_v}, {bounds.max_voltage_v}] V"
                )

        # 4. Current validation (finite, bounds)
        if isinstance(telemetry.current_a, bool) or not isinstance(telemetry.current_a, (int, float)):
            errors.append(f"current_a must be numeric, got {type(telemetry.current_a).__name__}")
        elif not math.isfinite(telemetry.current_a):
            errors.append(f"current_a must be a finite number; got {telemetry.current_a}")
        else:
            c = float(telemetry.current_a)
            if c < bounds.min_current_a or c > bounds.max_current_a:
                errors.append(
                    f"current_a {c} A out of bounds [{bounds.min_current_a}, {bounds.max_current_a}] A"
                )

        # 5. Optional Temperature validation
        if telemetry.temperature_c is not None:
            if isinstance(telemetry.temperature_c, bool) or not isinstance(
                telemetry.temperature_c, (int, float)
            ):
                errors.append(
                    f"temperature_c must be numeric or None, got {type(telemetry.temperature_c).__name__}"
                )
            elif not math.isfinite(telemetry.temperature_c):
                errors.append(f"temperature_c must be a finite number; got {telemetry.temperature_c}")
            else:
                t = float(telemetry.temperature_c)
                if t < bounds.min_temperature_c or t > bounds.max_temperature_c:
                    errors.append(
                        f"temperature_c {t} °C out of bounds [{bounds.min_temperature_c}, {bounds.max_temperature_c}] °C"
                    )

        # 6. Timestamp & Freshness validation
        if isinstance(telemetry.timestamp, bool) or not isinstance(telemetry.timestamp, (int, float)):
            errors.append(f"timestamp must be numeric POSIX timestamp, got {type(telemetry.timestamp).__name__}")
        elif not math.isfinite(telemetry.timestamp):
            errors.append(f"timestamp must be a finite number; got {telemetry.timestamp}")
        else:
            ts = float(telemetry.timestamp)
            if ts < 0:
                errors.append(f"timestamp must be a non-negative POSIX timestamp, got {ts}")
            else:
                age = ref_time - ts
                if age > bounds.max_age_seconds:
                    errors.append(
                        f"Telemetry is stale: reading is {age:.1f}s old (max allowable: {bounds.max_age_seconds}s)"
                    )
                elif age < -bounds.max_future_skew_seconds:
                    errors.append(
                        f"Telemetry timestamp is in the future ({abs(age):.1f}s ahead of clock)"
                    )


        is_valid = len(errors) == 0
        if not is_valid:
            logger.debug(
                "Physical telemetry validation failed for device '%s': %s",
                getattr(telemetry, "device_id", "unknown"),
                "; ".join(errors),
            )
        return ValidationResult(is_valid=is_valid, errors=errors)

    def validate_network(
        self,
        telemetry: Any,
        current_time: Optional[float] = None,
    ) -> ValidationResult:
        """Validate network telemetry record.

        Args:
            telemetry: The NetworkTelemetry instance to validate.
            current_time: Reference time for freshness check (defaults to time.time()).

        Returns:
            ValidationResult containing is_valid status and any errors.
        """
        errors: List[str] = []
        bounds = self.network_bounds
        ref_time = current_time if current_time is not None else time.time()

        if not isinstance(telemetry, NetworkTelemetry):
            errors.append(f"Expected NetworkTelemetry instance, got {type(telemetry).__name__}")
            return ValidationResult(is_valid=False, errors=errors)

        # 1. Source MAC validation
        if not isinstance(telemetry.source_mac, str) or not telemetry.source_mac.strip():
            errors.append("source_mac must be a non-empty string")

        # 2. Source IP validation
        if not isinstance(telemetry.source_ip, str) or not telemetry.source_ip.strip():
            errors.append("source_ip must be a non-empty string")

        # 3. Destination validation
        if not isinstance(telemetry.destination, str) or not telemetry.destination.strip():
            errors.append("destination must be a non-empty string")

        # 4. Protocol validation
        if not isinstance(telemetry.protocol, str) or not telemetry.protocol.strip():
            errors.append("protocol must be a non-empty string")

        # 5. Packet count validation
        if isinstance(telemetry.packet_count, bool) or not isinstance(telemetry.packet_count, int):
            errors.append(f"packet_count must be an integer, got {type(telemetry.packet_count).__name__}")
        elif telemetry.packet_count < bounds.min_packet_count or telemetry.packet_count > bounds.max_packet_count:
            errors.append(
                f"packet_count {telemetry.packet_count} out of bounds [{bounds.min_packet_count}, {bounds.max_packet_count}]"
            )

        # 6. Byte count validation
        if isinstance(telemetry.byte_count, bool) or not isinstance(telemetry.byte_count, int):
            errors.append(f"byte_count must be an integer, got {type(telemetry.byte_count).__name__}")
        elif telemetry.byte_count < bounds.min_byte_count or telemetry.byte_count > bounds.max_byte_count:
            errors.append(
                f"byte_count {telemetry.byte_count} out of bounds [{bounds.min_byte_count}, {bounds.max_byte_count}]"
            )

        # 7. Timestamp & Freshness validation
        if isinstance(telemetry.timestamp, bool) or not isinstance(telemetry.timestamp, (int, float)):
            errors.append(f"timestamp must be numeric POSIX timestamp, got {type(telemetry.timestamp).__name__}")
        elif not math.isfinite(telemetry.timestamp):
            errors.append(f"timestamp must be a finite number; got {telemetry.timestamp}")
        else:
            ts = float(telemetry.timestamp)
            if ts < 0:
                errors.append(f"timestamp must be a non-negative POSIX timestamp, got {ts}")
            else:
                age = ref_time - ts
                if age > bounds.max_age_seconds:
                    errors.append(
                        f"Telemetry is stale: reading is {age:.1f}s old (max allowable: {bounds.max_age_seconds}s)"
                    )
                elif age < -bounds.max_future_skew_seconds:
                    errors.append(
                        f"Telemetry timestamp is in the future ({abs(age):.1f}s ahead of clock)"
                    )


        # 8. Optional fields validation
        if telemetry.device_id is not None:
            if not isinstance(telemetry.device_id, str) or not telemetry.device_id.strip():
                errors.append("device_id must be None or a non-empty string")

        if telemetry.physical_port is not None:
            if isinstance(telemetry.physical_port, bool):
                errors.append("physical_port must be int, str, or None; got bool")
            elif isinstance(telemetry.physical_port, str):
                if not telemetry.physical_port.strip():
                    errors.append("physical_port as string must not be empty")
            elif not isinstance(telemetry.physical_port, int):
                errors.append("physical_port must be int, non-empty str, or None")

        if telemetry.source_port is not None:
            if isinstance(telemetry.source_port, bool) or not isinstance(telemetry.source_port, int):
                errors.append("source_port must be an integer in 1..65535 or None")
            elif telemetry.source_port < bounds.min_port or telemetry.source_port > bounds.max_port:
                errors.append(f"source_port {telemetry.source_port} out of range [1, 65535]")

        if telemetry.destination_port is not None:
            if isinstance(telemetry.destination_port, bool) or not isinstance(
                telemetry.destination_port, int
            ):
                errors.append("destination_port must be an integer in 1..65535 or None")
            elif (
                telemetry.destination_port < bounds.min_port
                or telemetry.destination_port > bounds.max_port
            ):
                errors.append(f"destination_port {telemetry.destination_port} out of range [1, 65535]")

        if telemetry.window_duration_s is not None:
            if isinstance(telemetry.window_duration_s, bool) or not isinstance(
                telemetry.window_duration_s, (int, float)
            ):
                errors.append("window_duration_s must be numeric or None")
            elif not math.isfinite(telemetry.window_duration_s) or telemetry.window_duration_s <= 0:
                errors.append("window_duration_s must be a positive finite number")

        is_valid = len(errors) == 0
        if not is_valid:
            logger.debug(
                "Network telemetry validation failed for source MAC '%s': %s",
                getattr(telemetry, "source_mac", "unknown"),
                "; ".join(errors),
            )
        return ValidationResult(is_valid=is_valid, errors=errors)


# Functional convenience shortcuts
_DEFAULT_VALIDATOR = TelemetryValidator()


def validate_physical_telemetry(
    telemetry: Any,
    bounds: Optional[PhysicalBoundsConfig] = None,
    current_time: Optional[float] = None,
) -> ValidationResult:
    """Convenience helper to validate physical telemetry."""
    validator = TelemetryValidator(physical_bounds=bounds) if bounds else _DEFAULT_VALIDATOR
    return validator.validate_physical(telemetry, current_time=current_time)


def validate_network_telemetry(
    telemetry: Any,
    bounds: Optional[NetworkBoundsConfig] = None,
    current_time: Optional[float] = None,
) -> ValidationResult:
    """Convenience helper to validate network telemetry."""
    validator = TelemetryValidator(network_bounds=bounds) if bounds else _DEFAULT_VALIDATOR
    return validator.validate_network(telemetry, current_time=current_time)
