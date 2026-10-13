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
├── pyproject.toml                 # Project metadata and pytest configuration
├── smart_backplane_antigravity_walkthrough.md # Architecture and staged specification
├── trust_engine/
│   ├── __init__.py                # Package exports
│   ├── states.py                  # Authoritative DeviceState enum & conversions
│   ├── device.py                  # Device dataclass with per-instance attributes
│   ├── registry.py                # Authoritative in-memory registry
│   └── telemetry.py               # Physical & network telemetry models and validation
├── tests/
│   ├── test_states.py             # Unit tests for state model & conversions
│   ├── test_device.py             # Unit tests for Device dataclass & validation
│   ├── test_registry.py           # Unit tests for registry, collisions & status ownership
│   └── test_telemetry.py          # Unit tests for telemetry schema, bounds & freshness
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

## 4. Running Tests & Logging

To run the full test suite with verbose output:

```bash
.venv/bin/pytest -v
```

Every test run automatically streams audit logs to `logs/pytest.log` with timestamps, severity levels, and validation failure records.

---

## 5. Stage Status

| Stage | Description | Status | Test Count |
|---|---|---|---|
| **Stage 1** | State model, Device dataclass, In-memory Registry | **Completed** | 18 passing |
| **Stage 2** | Telemetry schemas and validation | **Completed** | 35 passing |
| **Stage 3** | Policy engine & admission rules | Pending | - |
| **Stage 4** | Audit logging & simulated enforcement | Pending | - |

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

