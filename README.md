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
│   └── registry.py                # Authoritative in-memory registry
└── tests/
    ├── test_states.py             # Unit tests for state model & conversions
    ├── test_device.py             # Unit tests for Device dataclass & validation
    └── test_registry.py           # Unit tests for registry, collisions & status ownership
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

## 4. Running Tests

To run the full test suite with verbose output:

```bash
.venv/bin/pytest -v
```

Or when `.venv` is activated:

```bash
pytest -v
```

---

## 5. Stage Status

| Stage | Description | Status | Test Count |
|---|---|---|---|
| **Stage 1** | State model, Device dataclass, In-memory Registry | **Completed** | 18 passing |
| **Stage 2** | Telemetry schemas and validation | Pending | - |
| **Stage 3** | Policy engine & admission rules | Pending | - |
| **Stage 4** | Audit logging & simulated enforcement | Pending | - |

---

## 6. Stage 1 Quickstart Example

```python
from trust_engine import Device, DeviceRegistry, DeviceState

# 1. Initialize authoritative registry
registry = DeviceRegistry()

# 2. Register an observed device (even if device payload attempts to claim TRUSTED)
device = Device(
    device_id="dock-dev-01",
    mac_address="00:11:22:33:44:55",
    physical_port=1,
    status=DeviceState.TRUSTED,  # Untrusted claim
)

registered = registry.register(device)

# 3. Status is authoritatively enforced to QUARANTINED upon admission
print(registered.status)  # DeviceState.QUARANTINED

# 4. Authoritative transitions are performed solely by the registry/engine
registry.update_status("dock-dev-01", DeviceState.TRUSTED)
print(registry.get("dock-dev-01").status)  # DeviceState.TRUSTED
```
