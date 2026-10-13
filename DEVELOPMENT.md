# Smart Backplane Trust Engine --- Development Log

This document tracks the staged implementation, architectural decisions, and verification records for the Smart Backplane Trust Engine prototype.

---

## Stage Progress Summary

| Stage | Focus Area | Status | Passing Tests | Date Verified |
|---|---|---|---|---|
| **Stage 1** | State model, Device dataclass, In-memory Registry | **COMPLETED** | 18 / 18 | 2026-10-13 |
| **Stage 2** | Telemetry schemas & physical/network validation | *Queued* | - | - |
| **Stage 3** | Deterministic policy evaluation & engine | *Queued* | - | - |
| **Stage 4** | Audit logging & simulated enforcement adapter | *Queued* | - | - |

---

## Stage 1: State Model, Device Dataclass, and Registry

### 1. Architectural Objectives
- Establish the authoritative lifecycle enum (`DeviceState`) without typo traps (`ANOMALOUS`).
- Create an immutable/defensively copied `Device` dataclass ensuring zero shared state across instances.
- Build an authoritative in-memory `DeviceRegistry` keyed by `device_id` enforcing zero-trust status assignment and non-destructive duplicate collision handling.

### 2. Implemented Modules
- `trust_engine/states.py`: `DeviceState(str, Enum)` with `UNKNOWN`, `QUARANTINED`, `TRUSTED`, `ANOMALOUS`, `ISOLATED`, `REJECTED`, and case-insensitive normalization.
- `trust_engine/device.py`: `Device` dataclass validating fields on initialization and defaulting `status` to `QUARANTINED`.
- `trust_engine/registry.py`: `DeviceRegistry` handling registration, duplicate rejection, safe/strict lookups, status transitions, and MAC/port conflict detection.
- `trust_engine/__init__.py`: Package entry point exposing core classes and exceptions.

---

### 3. Detailed Audit of Conducted Tests (18 Tests)

All 18 tests are automated and executed with `pytest`. Below is the complete audit of every test case, what it executes, and what security/correctness property it validates.

#### A. State Model Tests (`tests/test_states.py`)

1. **`test_enum_members_exist_and_values`**
   - **Verification:** Ensures exactly 6 states exist: `UNKNOWN`, `QUARANTINED`, `TRUSTED`, `ANOMALOUS`, `ISOLATED`, `REJECTED`.
   - **Critical check:** Verifies exact spelling of `ANOMALOUS` (avoiding common typos like `ANOMALOUS` vs `ANOMALOUS`).
   - **Assertion:** Enum length is 6, attribute names match string values.

2. **`test_string_conversion`**
   - **Verification:** Tests string representation (`str(state)`) and `DeviceState.from_string()` helper.
   - **Critical check:** Verifies case-insensitivity (`"trusted"`, `"Isolated"`, `"rejected"`) and leading/trailing whitespace stripping (`"  QUARANTINED  "`).
   - **Assertion:** Returns exact enum singleton instances.

3. **`test_invalid_string_conversion_fails`**
   - **Verification:** Ensures illegal or malformed state strings cannot silently become valid states.
   - **Critical check:** Tests unrecognized strings (`"INVALID_STATE"`, `"UNTRUSTED"`), empty strings (`""`), and invalid data types (`None`, `12345`).
   - **Assertion:** Raises `ValueError` with informative message listing permissible states.

4. **`test_valid_states_set`**
   - **Verification:** Validates `DeviceState.valid_states()` returns all 6 state names in a set for validation helpers.

---

#### B. Device Model Tests (`tests/test_device.py`)

5. **`test_device_creation_with_defaults`**
   - **Verification:** Creates a device with required fields (`device_id`, `mac_address`, `physical_port`).
   - **Critical check:** Ensures `ip_address` defaults to `None`, and initial status defaults strictly to `DeviceState.QUARANTINED` (never trusted).

6. **`test_device_creation_with_all_fields`**
   - **Verification:** Tests creation with all optional fields provided, including string-based port IDs (`"dock-port-2"`) and custom valid initial states.

7. **`test_devices_have_independent_state`**
   - **Verification:** Directly verifies requirement: *"Device fields must be per-instance, not shared class attributes. Two devices have independent statuses."*
   - **Critical check:** Instantiates `dev1` and `dev2`. Modifies `dev1.status = TRUSTED` and `dev1.ip_address = "10.0.0.10"`.
   - **Assertion:** `dev2.status` remains `QUARANTINED`, `dev2.ip_address` remains `None`, and `dev1.__dict__ is not dev2.__dict__`.

8. **`test_device_status_string_normalization`**
   - **Verification:** Verifies that passing a string status (e.g. `"anomalous"`) to the constructor auto-normalizes via `__post_init__` into `DeviceState.ANOMALOUS`.

9. **`test_device_validation_errors`**
   - **Verification:** Tests input sanitization on constructor arguments.
   - **Critical check:** Blank `device_id`, blank `mac_address`, invalid/empty `physical_port`, empty `ip_address`, and unrecognized status strings.
   - **Assertion:** Raises `ValueError` on all invalid inputs.

10. **`test_device_to_dict`**
    - **Verification:** Verifies dictionary serialization (`to_dict()`) generates clean key-value structures ready for logging and audit serialization.

---

#### C. Registry Tests (`tests/test_registry.py`)

11. **`test_unique_registration_succeeds`**
    - **Verification:** Confirms normal registration of a valid device into the in-memory registry.
    - **Assertion:** Device is stored, `len(registry) == 1`, `"dev-001" in registry` is `True`.

12. **`test_duplicate_id_fails_without_overwrite`**
    - **Verification:** Directly verifies requirement: *"Duplicate IDs must fail clearly and never overwrite the existing record."*
    - **Critical check:** Registers device `dev-001` with MAC `00:11:22:33:44:55` on port 1. Then attempts to register a new conflicting payload with the same `device_id="dev-001"` but different MAC `AA:BB:CC:DD:EE:FF` on port 2.
    - **Assertion:** Raises `DuplicateDeviceError`. Querying the registry confirms the original MAC (`00:11:22:33:44:55`) and port 1 remain unchanged. Total registry size remains 1.

13. **`test_missing_id_lookup_behaviour`**
    - **Verification:** Directly verifies requirement: *"Define missing-ID lookup behaviour."*
    - **Defined behaviors tested:**
      1. `registry.get("missing")` returns `None` safely without exception.
      2. `registry.get("missing", default=default_dev)` returns the specified fallback.
      3. `registry.lookup("missing")` strictly raises `DeviceNotFoundError`.
      4. `registry["missing"]` dictionary syntax raises `DeviceNotFoundError`.
      5. `DeviceNotFoundError` inherits from `KeyError`, maintaining Python dictionary compatibility.
      6. `"missing" in registry` evaluates to `False`.

14. **`test_device_supplied_trusted_status_is_rejected_and_quarantined`**
    - **Verification:** Directly verifies requirement: *"Trust status is owned by the engine/registry. Never trust a device-supplied status field or allow it to set itself TRUSTED."*
    - **Critical check:** An untrusted device payload attempting to register with `status=DeviceState.TRUSTED`.
    - **Assertion:** Registered device status in the registry is overridden to `DeviceState.QUARANTINED`, refusing the unearned claim of trust.

15. **`test_registry_defensive_copies_prevent_external_tampering`**
    - **Verification:** Ensures external callers holding object references cannot mutate the internal registry state.
    - **Critical check:**
      1. Mutating the local `Device` object passed into `registry.register()` does not affect the registry.
      2. Mutating a `Device` object returned by `registry.get()` does not affect the registry.
      3. Mutating a `Device` object returned by `registry.lookup()` does not affect the registry.
    - **Assertion:** Stored device status remains untouched in all cases.

16. **`test_authoritative_status_update`**
    - **Verification:** Verifies that the authoritative engine method `update_status(device_id, new_status)` successfully updates the device lifecycle state.
    - **Assertion:** Can transition to `TRUSTED` and `ANOMALOUS`; raises `DeviceNotFoundError` on missing devices; raises `ValueError` on invalid state inputs.

17. **`test_mac_and_port_conflict_detection`**
    - **Verification:** Verifies requirement: *"Flag unexpected MAC/port associations as conflicts."*
    - **Critical check:** Checks `registry.check_conflicts(device)` when a different device claims the same physical port or same MAC.
    - **Assertion:** Port conflicts and MAC conflicts are detected; registering with `reject_conflicts=True` raises `DeviceConflictError`.

18. **`test_list_and_iteration`**
    - **Verification:** Verifies `len(registry)`, `list(registry)` iterating device IDs, `list_devices()` returning defensive copies, and `clear()`.

---

### 4. Test Execution Command & Verification

**Test Execution Command:**
```bash
.venv/bin/pytest -v
```

**Verification Output:**
```text
============================= test session starts ==============================
platform darwin -- Python 3.15.0, pytest-9.1.1, pluggy-1.6.0 -- /Users/balajipratyush4/Desktop/backplane/.venv/bin/python3.15
cachedir: .pytest_cache
rootdir: /Users/balajipratyush4/Desktop/backplane
configfile: pyproject.toml
testpaths: tests
collecting ... collected 18 items

tests/test_device.py::test_device_creation_with_defaults PASSED          [  5%]
tests/test_device.py::test_device_creation_with_all_fields PASSED        [ 11%]
tests/test_device.py::test_devices_have_independent_state PASSED         [ 16%]
tests/test_device.py::test_device_status_string_normalization PASSED     [ 22%]
tests/test_device.py::test_device_validation_errors PASSED               [ 27%]
tests/test_device.py::test_device_to_dict PASSED                         [ 33%]
tests/test_registry.py::test_unique_registration_succeeds PASSED         [ 38%]
tests/test_registry.py::test_duplicate_id_fails_without_overwrite PASSED [ 44%]
tests/test_registry.py::test_missing_id_lookup_behaviour PASSED          [ 50%]
tests/test_registry.py::test_device_supplied_trusted_status_is_rejected_and_quarantined PASSED [ 55%]
tests/test_registry.py::test_registry_defensive_copies_prevent_external_tampering PASSED [ 61%]
tests/test_registry.py::test_authoritative_status_update PASSED          [ 66%]
tests/test_registry.py::test_mac_and_port_conflict_detection PASSED      [ 72%]
tests/test_registry.py::test_list_and_iteration PASSED                   [ 77%]
tests/test_states.py::test_enum_members_exist_and_values PASSED          [ 83%]
tests/test_states.py::test_string_conversion PASSED                      [ 88%]
tests/test_states.py::test_invalid_string_conversion_fails PASSED        [ 94%]
tests/test_states.py::test_valid_states_set PASSED                       [100%]

============================== 18 passed in 0.03s ==============================
```

---

### 5. Next Stage
- **Stage 2 (Prompt 2):** Telemetry Schemas and Validation (`trust_engine/telemetry.py` and `tests/test_telemetry.py`).
