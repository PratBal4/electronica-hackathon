# Smart Backplane Trust Engine

Authoritative device admission, telemetry validation, and trust evaluation engine designed for the Smart Backplane dock monitor on Raspberry Pi 3B+ (Raspberry Pi OS / Debian, Python 3).

---

## 1. Overview & Architecture

The Smart Backplane monitors devices connected to physical dock ports. The Trust Engine runs on the Raspberry Pi and acts as the central authority for device admission and monitoring:
- **Authoritative Registry:** Tracks all docked devices keyed by `device_id`.
- **State Machine:** Owns device lifecycle transitions (`UNKNOWN`, `QUARANTINED`, `TRUSTED`, `ANOMALOUS`, `ISOLATED`, `REJECTED`).
- **Zero-Trust Input:** Devices cannot grant themselves trust or dictate their state. All newly connected devices begin in `QUARANTINED`.
- **Evidence-Based:** Telemetry from the INA3221 physical power monitor and network metadata serve as evidence, not proof of cryptographic identity.

```text
Docked device ── network traffic ──> Raspberry Pi
                                      │
                                Trust Engine
                         ┌────────────┼────────────┐
                         │            │            │
                      Registry     Policy       Audit log
                         │         engine
                         └────────────┼────────────┘
                                      │
                             Enforcement interface
                              (simulation first)
```

---

## 2. Project Layout

```text
backplane/
├── README.md                      # Project documentation and guide
├── DEVELOPMENT.md                 # Stage-by-stage development log and test audit
├── main.py                        # Executable CLI demonstration entrypoint
├── pyproject.toml                 # Project metadata and pytest configuration
├── smart_backplane_antigravity_walkthrough.md # Architecture and staged specification
├── trust_engine/
│   ├── __init__.py                # Package exports
│   ├── states.py                  # Authoritative DeviceState enum & conversions
│   ├── device.py                  # Device dataclass with per-instance attributes
│   ├── registry.py                # Authoritative in-memory registry
│   ├── telemetry.py               # Physical & network telemetry models and validation
│   ├── policy.py                  # Deterministic admission and monitoring policy rules
│   ├── engine.py                  # Central TrustEngine orchestrator & state machine
│   ├── audit.py                   # Structured zero-secret audit event logging
│   ├── enforcement.py             # Narrow enforcement interface & safe simulation adapter
│   └── simulator.py               # Deterministic scenario simulator runner
├── tests/
│   ├── test_states.py             # Unit tests for state model & conversions
│   ├── test_device.py             # Unit tests for Device dataclass & validation
│   ├── test_registry.py           # Unit tests for registry, collisions & status ownership
│   ├── test_telemetry.py          # Unit tests for telemetry schema, bounds & freshness
│   ├── test_policy.py             # Unit tests for policy rules, decisions & reason codes
│   ├── test_engine.py             # Integration tests for transitions & TrustEngine
│   ├── test_audit.py              # Unit tests for audit logging & secret scrubbing
│   ├── test_enforcement.py        # Safety tests proving no system/GPIO calls occur
│   └── test_simulator.py          # Scenario verification for admission & isolation
└── logs/
    └── pytest.log                 # Test execution and Trust Engine audit logs
```

---

## 3. Setup & Installation

### Prerequisites
- Python 3.9+ (tested on Python 3.11+ / 3.15)
- Standard library only for application runtime (zero external runtime dependencies)

### Local Environment Setup

```bash
# Clone or navigate to the repository directory
cd /path/to/backplane

# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install development dependencies (pytest)
pip install pytest
```

---

## 4. Running Tests & Demonstration CLI

### Run Test Suite
To run all 70 automated tests:

```bash
.venv/bin/pytest -v
```

Execution logs are streamed into `logs/pytest.log` with timestamps and audit records.

### Run Demonstration Simulator CLI
To run the interactive demonstration scenarios:

```bash
python main.py
```

---

## 5. Stage Status

| Stage | Description | Status | Test Count |
|---|---|---|---|
| **Stage 1** | State model, Device dataclass, In-memory Registry | **Completed** | 18 passing |
| **Stage 2** | Telemetry schemas and validation | **Completed** | 35 passing |
| **Stage 3** | Policy engine & admission rules | **Completed** | 56 passing |
| **Stage 4** | Audit logging, simulator & simulated enforcement | **Completed** | 70 passing |



---

## 6. Quickstart Examples

### Registry & Device Lifecycle (Stage 1)

```python
from trust_engine import Device, DeviceRegistry, DeviceState

registry = DeviceRegistry()

# Register observed device (device cannot self-appoint TRUSTED status)
device = Device(
    device_id="dock-dev-01",
    mac_address="00:11:22:33:44:55",
    physical_port=1,
    status=DeviceState.TRUSTED,  # Untrusted claim
)
registered = registry.register(device)
print(registered.status)  # DeviceState.QUARANTINED

# Engine authoritatively transitions status
registry.update_status("dock-dev-01", DeviceState.TRUSTED)
print(registry.get("dock-dev-01").status)  # DeviceState.TRUSTED
```

### Telemetry Schema & Bounds Validation (Stage 2)

```python
import time
from trust_engine import (
    PhysicalTelemetry,
    NetworkTelemetry,
    validate_physical_telemetry,
    validate_network_telemetry,
)

# 1. Validate physical reading (voltage, current, optional temp, freshness)
phys = PhysicalTelemetry(
    device_id="dock-dev-01",
    physical_port=1,
    voltage_v=5.02,
    current_a=0.45,
    timestamp=time.time(),
    temperature_c=36.2,
)
phys_result = validate_physical_telemetry(phys)
assert phys_result.is_valid is True

# 2. Invalid readings (e.g. out of bounds or NaN) are safely flagged without crashing
invalid_phys = PhysicalTelemetry(
    device_id="dock-dev-01",
    physical_port=1,
    voltage_v=28.0,  # Exceeds max allowable dock voltage
    current_a=0.5,
    timestamp=time.time(),
)
invalid_result = validate_physical_telemetry(invalid_phys)
assert invalid_result.is_valid is False
print(invalid_result.errors)
# ['voltage_v 28.0 V out of bounds [0.0, 24.0] V']
```

### Policy Evaluation & Trust Engine Orchestration (Stage 3)

```python
import time
from trust_engine import (
    Device,
    TrustEngine,
    PhysicalTelemetry,
    NetworkTelemetry,
)

engine = TrustEngine()

# 1. Register newly detected device into quarantine
device = Device(device_id="dock-cam-01", mac_address="00:11:22:33:44:55", physical_port=1)
engine.register_device(device)
print(engine.registry.get("dock-cam-01").status)  # DeviceState.QUARANTINED

# 2. Evaluate admission with compliant telemetry
now = time.time()
phys = [PhysicalTelemetry("dock-cam-01", 1, 5.05, 0.45, now)]
net = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.5", "10.0.0.1", "TCP", 30, 2500, now)]

decision = engine.evaluate_admission("dock-cam-01", phys, net)
print(decision.decision_type)  # DecisionType.ALLOW
print(engine.registry.get("dock-cam-01").status)  # DeviceState.TRUSTED

# 3. Behavioral monitoring flags severe violations and isolates immediately
bad_net = [NetworkTelemetry("00:11:22:33:44:55", "10.0.0.5", "botnet.c2", "TCP", 10, 500, now)]
mon_decision = engine.evaluate_monitoring("dock-cam-01", network_telemetry=bad_net)
print(mon_decision.decision_type)  # DecisionType.ISOLATE
print(engine.registry.get("dock-cam-01").status)  # DeviceState.ISOLATED
```

---

## 7. Safety Guarantee: Simulated vs. Real Enforcement

> [!IMPORTANT]
> **SIMULATED ENFORCEMENT ONLY:**
> This repository implements a safe, testable software prototype. The `SimulatedEnforcementAdapter` **only records actions in-memory**. It explicitly performs:
> - **NO** Linux firewall (`iptables` / `nftables`) modifications.
> - **NO** network interface or routing table reconfigurations (protecting your Raspberry Pi Connect remote session).
> - **NO** Raspberry Pi GPIO pin toggling or INA3221 hardware power cutting.
>
> All enforcement requests return structured `EnforcementResult` records stamped with `is_simulation = True`.

---

## 8. Honest Limitations & Remaining Integration Work

### Honest Scope & Limitations
- **MAC Addresses Are Not Identity Proof:** Observed MAC addresses can be spoofed; MAC association is treated as correlation evidence, not cryptographic authentication.
- **Normal Telemetry Does Not Prove Innocence:** Compliant voltage or packet counts do not guarantee a device has not been compromised.
- **Local Logs Are Not Tamper-Proof:** Local file logs on Raspberry Pi OS can be modified if an adversary gains root access.
- **Traffic Visibility Boundary:** The Trust Engine cannot inspect encrypted payload contents (TLS/HTTPS); policy operates exclusively on network metadata (endpoints, ports, byte/packet volumes).

### Remaining Work for Real Hardware Integration (Phase 2)
1. **ESP32 & INA3221 Transport Driver:** Implement a robust serial/UART or authenticated framing driver to consume synthetic/real INA3221 readings safely without blocking.
2. **Linux Packet Capture Adapter:** Integrate an eBPF, `tshark`, or socket-based passive metadata collector to produce `NetworkTelemetry` records without altering routing.
3. **Dedicated Lab Firewall Rules:** In an isolated network testbed (with out-of-band serial recovery), implement real `nftables` quarantine chains.
4. **Hardware Port Switching:** Validate low-voltage MOSFET / relay power switching on separate bench supplies before allowing autonomous Trust Engine software control.


