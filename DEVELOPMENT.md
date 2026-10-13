# Smart Backplane Trust Engine --- Development Log

This document tracks the staged implementation, architectural decisions, and verification records for the Smart Backplane Trust Engine prototype.

---

## Stage Progress Summary

| Stage | Focus Area | Status | Passing Tests | Date Verified |
|---|---|---|---|---|
| **Stage 1** | State model, Device dataclass, In-memory Registry | **COMPLETED** | 18 / 18 | 2026-10-13 |
| **Stage 2** | Telemetry schemas & physical/network validation | **COMPLETED** | 35 / 35 | 2026-10-13 |
| **Stage 3** | Deterministic policy evaluation & engine | **COMPLETED** | 56 / 56 | 2026-10-13 |
| **Stage 4** | Audit logging & simulated enforcement adapter | **COMPLETED** | 70 / 70 | 2026-10-13 |
| **Stage 5** | Formal security audit & boundary invariant review | **COMPLETED** | 75 / 75 | 2026-10-13 |





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

## Stage 2: Telemetry Schemas and Validation

### 1. Architectural Objectives
- **Separate Physical and Network Schemas:** Maintain clean separation between physical power/sensor data (`PhysicalTelemetry`) and network traffic observations (`NetworkTelemetry`).
- **Explicit Units & Types:** Units are explicitly encoded in field names (`voltage_v`, `current_a`, `temperature_c`, `window_duration_s`) to eliminate ambiguity.
- **Strict Decoupling:** Validation validates schema conformity, type correctness, finite bounds, and freshness. It is strictly decoupled from policy decisions (valid telemetry constitutes evidence, but never dictates policy admission on its own).
- **Honest Security Scope:** Normal power consumption or network traffic is observable evidence, never cryptographic proof of identity.
- **Finite Number Guarantees:** Strict rejection of `NaN`, `+Infinity`, and `-Infinity` across all numeric measurements.
- **Freshness Thresholds:** Readings older than `max_age_seconds` (stale data) or significantly ahead of clock (future skew) are rejected.

### 2. Implemented Modules
- `trust_engine/telemetry.py`:
  - `PhysicalTelemetry`: Dataclass capturing `device_id`, `physical_port`, `voltage_v`, `current_a`, `timestamp`, and optional `temperature_c`.
  - `NetworkTelemetry`: Dataclass capturing `source_mac`, `source_ip`, `destination`, `protocol`, `packet_count`, `byte_count`, `timestamp`, and optional `device_id`, `physical_port`, `source_port`, `destination_port`, `window_duration_s`.
  - `PhysicalBoundsConfig` & `NetworkBoundsConfig`: Configurable boundary definitions for sensor validation.
  - `ValidationResult`: Structured result object containing `is_valid`, `errors`, `warnings`, and helper `raise_if_invalid()`.
  - `TelemetryValidator`: Deterministic validator class and helper functions `validate_physical_telemetry` and `validate_network_telemetry`.

---

### 3. Detailed Audit of Conducted Tests (17 Telemetry Tests, 35 Total)

All 17 new telemetry tests are automated via `tests/test_telemetry.py`.

#### A. Valid Telemetry Records
1. **`test_valid_physical_telemetry_accepted`**
   - Asserts a compliant physical record (5.05V, 0.45A, current timestamp, 36.5°C) passes validation without errors.
2. **`test_valid_physical_telemetry_without_optional_temperature`**
   - Asserts physical telemetry with `temperature_c=None` passes validation.
3. **`test_valid_network_telemetry_accepted`**
   - Asserts compliant network telemetry (TCP, packet/byte counts, transport ports, window duration) passes validation.

#### B. Type & Missing Field Validation
4. **`test_physical_telemetry_wrong_type_rejected`**
   - Asserts non-`PhysicalTelemetry` objects (e.g. dicts) fail validation immediately.
5. **`test_physical_telemetry_missing_or_invalid_fields`**
   - Asserts empty `device_id`, boolean port (`True`), string voltage (`"5.0"`), and boolean voltage (`False`) fail validation.
6. **`test_network_telemetry_wrong_types_rejected`**
   - Asserts empty MAC address and boolean packet counts fail validation.

#### C. Out-of-Range and Configurable Bounds
7. **`test_physical_telemetry_out_of_bounds`**
   - Asserts excessive voltage (28V on 24V limit), negative voltage (-1V), excessive current (10A on 5A limit), and out-of-range temperature (150°C) fail validation.
8. **`test_physical_telemetry_custom_configurable_bounds`**
   - Asserts custom tight USB 5V rail bounds (`4.75V - 5.25V`) successfully reject 4.60V.
9. **`test_network_telemetry_out_of_bounds`**
   - Asserts negative packet count (-5) and out-of-range transport ports (70000) fail validation.

#### D. Finite Number Checks (Rejection of NaN & Infinity)
10. **`test_physical_telemetry_rejects_nan_and_infinity`**
    - Asserts `NaN` voltage, `+Inf` current, `-Inf` temperature, and `NaN` timestamp fail validation.
11. **`test_network_telemetry_rejects_nan_and_infinity`**
    - Asserts `NaN` timestamp and `+Inf` window duration in network telemetry fail validation.

#### E. Freshness & Stale Data
12. **`test_physical_telemetry_stale_reading_rejected`**
    - Asserts physical readings older than `max_age_seconds` (120s old vs 60s limit) are flagged as stale and rejected.
13. **`test_physical_telemetry_future_timestamp_rejected`**
    - Asserts timestamps significantly ahead of reference clock (30s in the future vs 5s limit) fail validation.
14. **`test_network_telemetry_stale_reading_rejected`**
    - Asserts stale network telemetry readings are rejected.

#### F. Optional Fields & Helpers
15. **`test_network_telemetry_optional_fields_behavior`**
    - Asserts optional fields default to `None` when omitted, and verifies invalid optional fields (blank device_id, port 0) are caught.
16. **`test_validation_result_raise_if_invalid`**
    - Asserts `ValidationResult.raise_if_invalid()` raises `TelemetryValidationError` when errors exist, and is a no-op when valid.
17. **`test_telemetry_serialization`**
    - Asserts `to_dict()` outputs clean dictionaries for physical and network records.

---

### 4. Logging System Verification

Every test run writes structured execution and debug logs into `logs/pytest.log`:
```text
2026-10-13 11:04:36 [INFO] trust_engine.registry: Registered device 'dev-001' on port 1 (status: QUARANTINED)
2026-10-13 11:04:36 [WARNING] trust_engine.registry: Device 'rogue-001' attempted to register with status TRUSTED. Overriding to QUARANTINED.
2026-10-13 11:04:36 [DEBUG] trust_engine.telemetry: Physical telemetry validation failed for device 'dev-1': voltage_v 28.0 V out of bounds [0.0, 24.0] V
2026-10-13 11:04:36 [DEBUG] trust_engine.telemetry: Physical telemetry validation failed for device 'dev-1': voltage_v must be a finite number; got nan
2026-10-13 11:04:36 [DEBUG] trust_engine.telemetry: Physical telemetry validation failed for device 'dev-1': Telemetry is stale: reading is 120.0s old (max allowable: 60.0s)
```

---

## Stage 3: Deterministic Policy Evaluation and Trust Engine Orchestration

### 1. Architectural Objectives
- **Explicit & Explainable Rules:** Zero machine learning and zero opaque confidence scores. Decisions output structured verdicts with explicit programmatic `reason_codes`, human-readable `explanation`, and an `evidence_summary`.
- **Centralized & Authoritative State Transitions:** Transition rules are strictly centralized (`ALLOWED_TRANSITIONS`). Transitions skipping intermediate states or moving from terminal states raise `IllegalStateTransitionError`.
- **Reason Required:** Every single state transition and policy verdict requires an explicit, documented reason.
- **Decoupled Identity vs Behaviour:** Identity validation (dock port / MAC binding conflicts) is distinct from behavioral monitoring (current consumption, packet rates, destinations).
- **Mild Anomalies vs Severe Violations:** A single mild anomaly flags the device as `ANOMALOUS` for continuous monitoring without immediate rejection. Only severe policy breaches (prohibited C2 endpoints, massive exfiltration bursts) or repeated anomalies exceeding threshold (`> max_mild_anomalies`) trigger `ISOLATE`.
- **Admission Timeout without Malice:** Timeout ends the admission quarantine attempt with reason `ADMISSION_TIMEOUT` while explicitly acknowledging that timeout alone is not proof of malice.

### 2. Physical Reality vs. Automated Unit Testing
A key question during embedded software development is: *Why do software tests pass without real hardware connected, and where would real hardware fail?*
- **Why tests pass now:** Unit tests construct deterministic in-memory synthetic records (`PhysicalTelemetry`, `NetworkTelemetry`). This tests the *software decision logic* in pure isolation from hardware volatility.
- **Where real hardware will encounter failures:**
  1. *Loose sensor wiring / I2C bus noise:* Disconnected INA3221 lines cause I2C timeouts or return floating ADC bits resulting in `NaN` or infinite values. Stage 2's finite number checks (`math.isnan`) protect the engine from crashing on these.
  2. *Inrush current spikes:* Devices plugging into physical dock ports draw an initial surge of current (e.g., 3.5A charging capacitors) before settling down. Stage 3's admission policy requires continuous validated readings over an observation window.
  3. *Unsynchronized RTC clock drift:* ESP32 boards booting without NTP can transmit timestamps from epoch 1970 or skewed by hours. Stage 2's freshness validator catches this (`max_age_seconds: 60s`, `max_future_skew: 5s`).
  4. *Physical port contention:* If a user plugs a passive USB hub into a dock port, two physical devices share one dock port. Stage 1 & Stage 3's `check_conflicts()` and `IDENTITY_CONFLICT` rules explicitly catch this condition.

### 3. Implemented Modules
- `trust_engine/policy.py`:
  - `DecisionType`: `ALLOW`, `KEEP_QUARANTINED`, `ANOMALOUS`, `ISOLATE`, `REJECT`.
  - `PolicyDecision`: Structured output with `decision_type`, `recommended_state`, `reason_codes`, `explanation`, and `evidence_summary`.
  - `PolicyConfig`: Configurable parameters (timeout, baseline voltage/current ranges, max anomalies, prohibited destinations/ports/protocols).
  - `PolicyEngine`: Pure deterministic rule evaluation for admission and active monitoring.
- `trust_engine/engine.py`:
  - `ALLOWED_TRANSITIONS`: Centralized state transition graph.
  - `IllegalStateTransitionError`: Exception preventing illegal or out-of-order state jumps.
  - `TrustEngine`: Orchestrates device registration, telemetry filtering, policy evaluation, state transitions, and audit history.

---

### 4. Detailed Audit of Conducted Tests (21 New Tests, 56 Total)

#### A. Policy Rule Tests (`tests/test_policy.py` — 10 tests)
1. **`test_insufficient_evidence_keeps_quarantined`**: Asserts missing telemetry (no data, only physical, or only network) returns `KEEP_QUARANTINED` with `INSUFFICIENT_EVIDENCE`.
2. **`test_successful_admission_under_defined_rules`**: Asserts compliant telemetry yields `ALLOW`, recommending `TRUSTED` with `ADMISSION_PASSED`.
3. **`test_identity_conflict_prevents_admission`**: Asserts MAC or port conflict immediately returns `REJECT` with `IDENTITY_CONFLICT`.
4. **`test_admission_timeout_ends_attempt_without_malice`**: Asserts elapsed time exceeding 30s returns `REJECT` with `ADMISSION_TIMEOUT` and notes timeout is not proof of malice.
5. **`test_physical_baseline_violation_rejects_admission`**: Asserts out-of-spec voltage (4.2V vs 4.75V min) returns `REJECT` with `PHYSICAL_BASELINE_OUT_OF_SPEC`.
6. **`test_prohibited_network_rules_reject_admission`**: Asserts prohibited destination (`botnet.c2`), protocol (`TELNET`), or port (`1337`) returns `REJECT`.
7. **`test_mild_anomaly_does_not_automatically_reject`**: Asserts elevated current (2.8A vs 2.5A) returns `ANOMALOUS` for observation, not immediate isolation.
8. **`test_repeated_anomalies_exceeding_threshold_triggers_isolation`**: Asserts 3rd consecutive anomaly (exceeding threshold of 2) triggers `ISOLATE` with `REPEATED_ANOMALIES_EXCEEDED`.
9. **`test_severe_network_violations_trigger_immediate_isolation`**: Asserts exfiltration burst (15MB) or C2 communication triggers `ISOLATE` with `SEVERE_VIOLATION`.
10. **`test_normal_monitoring_maintains_trusted`**: Asserts healthy telemetry during monitoring returns `ALLOW` with `BEHAVIOR_NORMAL`.

#### B. Trust Engine Orchestration Tests (`tests/test_engine.py` — 11 tests)
11. **`test_allowed_transitions_table_integrity`**: Validates the transition graph table matches the architectural specification.
12. **`test_illegal_state_transitions_are_rejected`**: Asserts illegal transitions (`QUARANTINED -> ISOLATED`, `QUARANTINED -> ANOMALOUS`) raise `IllegalStateTransitionError`, and blank reasons raise `ValueError`.
13. **`test_only_trust_engine_can_mark_device_trusted`**: Asserts rogue device registering with `status=TRUSTED` remains `QUARANTINED`; only engine admission can transition to `TRUSTED`.
14. **`test_engine_admission_insufficient_evidence_stays_quarantined`**: Asserts lack of evidence keeps the device in `QUARANTINED` in the registry.
15. **`test_engine_admission_success_transitions_to_trusted`**: Asserts compliant telemetry authoritatively transitions the device to `TRUSTED`.
16. **`test_engine_admission_identity_conflict_transitions_to_rejected`**: Asserts port collision transitions device to `REJECTED`.
17. **`test_engine_admission_timeout_transitions_to_rejected`**: Asserts timeout transitions device to `REJECTED`.
18. **`test_engine_monitoring_mild_anomaly_transitions_to_anomalous`**: Asserts mild current surge transitions device from `TRUSTED` to `ANOMALOUS`.
19. **`test_engine_monitoring_repeated_anomalies_transitions_to_isolated`**: Asserts repeated anomalies trigger transition from `ANOMALOUS` to `ISOLATED`.
20. **`test_engine_monitoring_severe_violation_transitions_to_isolated`**: Asserts severe violation triggers immediate transition from `TRUSTED` to `ISOLATED`.
21. **`test_engine_transition_history_audit`**: Verifies transition history records timestamps, from-state, to-state, and explicit reason strings for every lifecycle event.

---

## Stage 4: Audit Logging, Simulator, and Simulated Enforcement

### 1. Architectural Objectives
- **Zero-Secret Audit Trail:** Structured `AuditEvent` records scrub all sensitive credential keys (`api_key`, `password`, `token`, `private_key`) before storing or logging.
- **Narrow Enforcement Contract:** Abstract `EnforcementAdapter` defines exactly three operations: `isolate_device`, `restore_quarantine`, and `set_port_power`.
- **Purely Simulated Safety Guarantee:** `SimulatedEnforcementAdapter` performs **zero** shell commands, **zero** Linux firewall (`iptables`/`nftables`) modifications, and **zero** GPIO pin toggling.
- **Safe Failure Modes:** Invalid arguments (empty IDs/reasons, non-positive ports) and unknown devices fail safely without crashing the service.
- **End-to-End Deterministic Scenarios:** `Simulator` and `main.py` run 3 distinct scenarios: normal admission, insufficient evidence quarantine, and policy violation isolation.

### 2. Implemented Modules
- `trust_engine/audit.py`:
  - `AuditEvent`: Structured dataclass with `event_id`, `event_type`, `timestamp`, `device_id`, `reason_code`, `details`, and `severity`.
  - `AuditLog`: Append-only in-memory log with query filtering and Python `logging` mirroring.
  - `sanitize_audit_data`: Recursive secret scrubbing utility.
- `trust_engine/enforcement.py`:
  - `EnforcementActionType`: Enum of narrow actions (`ISOLATE_DEVICE`, `RESTORE_QUARANTINE`, `SET_PORT_POWER`).
  - `EnforcementResult`: Dataclass stamped with `is_simulation: True` and explicit execution status.
  - `EnforcementAdapter`: Abstract base class.
  - `SimulatedEnforcementAdapter`: In-memory implementation with input validation, registry lookup safety checks, and simulated failure injection (`simulate_failure=True`).
- `trust_engine/simulator.py`:
  - `Simulator`: Demonstrates Normal Admission, Insufficient Evidence, and Policy Violation Isolation.
  - `ScenarioResult`: Structured report for scenario verification.
- `main.py`:
  - Executable CLI entrypoint demonstrating all scenarios with safety disclaimers and formatted audit reports.

---

### 3. Detailed Audit of Conducted Tests (14 New Tests, 70 Total)

#### A. Audit Logging Tests (`tests/test_audit.py` — 3 tests)
1. **`test_audit_event_recording_and_querying`**: Asserts event recording with unique UUIDs and querying filtered by `device_id` or `event_type`.
2. **`test_secret_scrubbing_guarantee`**: Asserts passwords, API keys, private keys, and user tokens are redacted as `[REDACTED]` in flat and nested structures.
3. **`test_audit_event_serialization`**: Asserts `to_dict()` produces correct serializable audit event representations.

#### B. Enforcement Safety Tests (`tests/test_enforcement.py` — 7 tests)
4. **`test_isolate_device_recorded_successfully`**: Asserts `isolate_device` records simulated action with `is_simulation: True`.
5. **`test_restore_quarantine_recorded_successfully`**: Asserts `restore_quarantine` records simulated action.
6. **`test_set_port_power_recorded_successfully`**: Asserts `set_port_power` records power requests without physical switching.
7. **`test_unknown_device_fails_safely`**: Asserts querying an unknown device ID fails safely with `success: False` rather than raising uncaught exceptions.
8. **`test_invalid_arguments_fail_safely`**: Asserts blank IDs, blank reasons, and invalid port numbers (0, negative, bool) return safe failure results.
9. **`test_simulated_adapter_failure_handled_safely`**: Asserts adapter fault injection records `ADAPTER_COMMUNICATION_ERROR` in the audit log.
10. **`test_safety_guarantee_no_system_or_gpio_calls_occurred`**: Patches `subprocess.run`, `subprocess.Popen`, and `os.system` to prove no system calls occur during enforcement.

#### C. Simulator Scenario Tests (`tests/test_simulator.py` — 4 tests)
11. **`test_scenario_normal_admission`**: Asserts Scenario 1 transitions `QUARANTINED -> TRUSTED` with verdict `ALLOW`.
12. **`test_scenario_insufficient_evidence`**: Asserts Scenario 2 retains device in `QUARANTINED` with verdict `KEEP_QUARANTINED`.
13. **`test_scenario_policy_violation_isolation`**: Asserts Scenario 3 transitions `TRUSTED -> ISOLATED` with verdict `ISOLATE` and recorded simulated enforcement.
14. **`test_run_all_scenarios`**: Asserts running all scenarios executes all 3 lifecycles deterministically.

---

### 4. Definition of Done Checklist Verification

- [x] **Device registry works; duplicate IDs cannot overwrite records.** (`DuplicateDeviceError` tested and verified).
- [x] **New devices enter quarantine.** (`DeviceState.QUARANTINED` default enforced).
- [x] **Telemetry is validated before policy evaluation.** (`TelemetryValidator` rejects out-of-bounds, NaN/Inf, and stale data).
- [x] **Decisions are deterministic and explainable.** (`PolicyEngine` generates programmatic reason codes and human-readable explanations).
- [x] **Insufficient evidence remains quarantined.** (`KEEP_QUARANTINED` verdict enforced).
- [x] **A policy violation can trigger simulated isolation.** (`ISOLATE` verdict triggers `SimulatedEnforcementAdapter.isolate_device`).
- [x] **Decisions and transitions are audited with reasons.** (`AuditLog` and `TrustEngine.get_transition_history` record explicit reasons).
- [x] **`python -m pytest -q` passes.** (All 70 tests pass in 0.04s).
- [x] **README distinguishes simulated from real enforcement.** (Safety guarantee banner added).
- [x] **Demo does not risk the Pi's network connection or physical hardware.** (Proven via test mock verification).

---

## Stage 5: Formal Security Audit & Boundary Invariant Review

### 1. Security Review Scope
In accordance with Section 11 of the Walkthrough specification (*Useful security-review prompt*), a comprehensive, forensic review of trust-state authority, duplicate IDs, invalid/stale telemetry, unsafe defaults, state transitions, shared mutable state, and boundary mutations was conducted across the codebase.

### 2. Ranked Findings & Applied Remediations

| Severity | ID | Finding & Description | Remediation Applied |
|:---:|:---:|---|---|
| **HIGH** | **SEC-01** | `TrustEngine.evaluate_monitoring()` did not check the device's initial lifecycle state, allowing unadmitted devices in `QUARANTINED` to be evaluated for monitoring and potentially transitioned to `TRUSTED` without passing admission rules. | Added state gate raising `ValueError` if `device.status not in (TRUSTED, ANOMALOUS)`. |
| **MEDIUM** | **SEC-02** | `TrustEngine.evaluate_admission()` allowed already `TRUSTED`, `ISOLATED`, or `REJECTED` devices to undergo admission evaluation instead of enforcing prior re-quarantine/re-docking. | Added state gate raising `ValueError` if `device.status not in (QUARANTINED, UNKNOWN)`. |
| **MEDIUM** | **SEC-03** | `DeviceRegistry.register()` checked and overridden device-supplied `TRUSTED` status, but allowed caller-supplied `ANOMALOUS` or `ISOLATED` states to be registered without prior quarantine. | Registry now enforces that *all* newly registered devices begin strictly in `QUARANTINED`, overriding any caller-supplied state. |
| **LOW** | **SEC-04** | `Device` identifier fields (`device_id`, `mac_address`, `physical_port`) validated non-empty whitespace but did not strip whitespace, permitting subtle alias collisions (e.g. `"dev-01 "` vs `"dev-01"`). | `Device.__post_init__` now strips leading/trailing whitespace across all identifier and address fields. |
| **LOW** | **SEC-05** | Negative POSIX timestamps (`ts < 0`) were not explicitly rejected in `TelemetryValidator`. | `validate_physical` and `validate_network` now reject `ts < 0` as invalid POSIX timestamps. |

### 3. Dedicated Security Test Suite (`tests/test_security_review.py` — 5 tests)
1. **`test_sec01_evaluate_monitoring_rejects_unadmitted_devices`**: Verifies that calling `evaluate_monitoring` on devices in `QUARANTINED` or `REJECTED` raises `ValueError`.
2. **`test_sec02_evaluate_admission_rejects_non_quarantined_devices`**: Verifies that calling `evaluate_admission` on `TRUSTED` devices raises `ValueError`.
3. **`test_sec03_registry_enforces_quarantine_for_all_untrusted_states`**: Verifies that registering devices with `status=ANOMALOUS` or `status=ISOLATED` forces `QUARANTINED`.
4. **`test_sec04_device_identifier_whitespace_normalization`**: Verifies that identifier strings with padding are stripped and normalized.
5. **`test_sec05_negative_timestamps_rejected`**: Verifies that negative timestamps fail telemetry validation.

**Total Verified Tests Across Repository:** **75 / 75 passing**.

---

## Stage 6: ESP32 Hardware Telemetry Transport, Frame Parser & Ingestion Pipeline

### 1. Architectural Scope & Problem Statement
The Smart Backplane physical dock monitors up to 3 dock ports using an INA3221 3-channel power monitor connected to an ESP32 microcontroller. The ESP32 streams raw telemetry lines over a UART/Serial link (`/dev/ttyS0` or `/dev/serial0`) to the Raspberry Pi 3B+.

Physical microcontroller-to-Pi serial communication presents distinct transport vulnerabilities and failure modes:
1. **Partial Reads & Chunk Fragmentation:** UART reads return arbitrary byte chunk sizes (e.g. 7 or 16 bytes), slicing JSON messages across read boundaries.
2. **Electrical Line Noise & Bit Flips:** UART transmissions without integrity checks can silently mutate float values (e.g. `5.0V` becoming `50.0V` or corrupting JSON syntax).
3. **Replay & Stale Sequence Frames:** Power hiccups or microcontroller resets can cause frame repetition or sequence regression.
4. **Runaway / Missing-Delimiter Streams:** Noise or stream desynchronization causing missing `\n` delimiters can lead to unbounded buffer memory exhaustion.
5. **Downstream Integration:** Raw frames must resolve to docked devices, undergo physical bounds verification, and feed into the Trust Engine without trusting client-asserted states.

### 2. Protocol Specification (Version 1)
Line-delimited JSON frames terminated by `\n` or `\r\n`:
```json
{
  "v": 1,
  "seq": 1042,
  "port": 1,
  "device_id": "dock-dev-01",
  "voltage_v": 5.08,
  "current_a": 0.44,
  "temp_c": 36.2,
  "timestamp": 1718000000.0,
  "crc32": "aa493142"
}
```

- **`v`**: Protocol version integer (strictly `1`).
- **`seq`**: Strictly monotonic sequence integer per monitored port.
- **`port`**: Physical dock port number (integer or string e.g. `1`, `2`, `3`).
- **`voltage_v`**: INA3221 bus voltage in Volts (finite float/int, not bool).
- **`current_a`**: INA3221 shunt current in Amperes (finite float/int, not bool).
- **`timestamp`**: POSIX epoch timestamp in seconds (`ts >= 0`).
- **`temp_c`**: Optional ambient/shunt thermistor reading in °C.
- **`device_id`**: Associated docked device. Resolved via explicit static map or `DeviceRegistry.list_devices()` if omitted.
- **`crc32`**: 8-character lowercase hexadecimal CRC-32 checksum computed over canonical JSON payload excluding `"crc32"`:
  `canonical_bytes = json.dumps({k: v for k, v in payload.items() if k != "crc32"}, sort_keys=True, separators=(',', ':')).encode('utf-8')`

### 3. Implementation Details
- **`trust_engine/esp32_transport.py`**:
  - `ESP32Frame`: Immutable dataclass representing parsed envelope.
  - `FrameErrorReason`: Categorized error taxonomy (`BUFFER_OVERFLOW`, `DECODE_ERROR`, `MALFORMED_JSON`, `UNSUPPORTED_VERSION`, `MISSING_FIELD`, `INVALID_FIELD_TYPE`, `NON_FINITE_VALUE`, `NEGATIVE_TIMESTAMP`, `CRC_MISMATCH`, `OUT_OF_SEQUENCE`, `UNMAPPED_PORT`, `VALIDATION_FAILED`).
  - `FrameParseError` & `FrameParseResult`: Structured failure/success containers.
  - `compute_frame_crc32()` & `format_esp32_frame()`: Deterministic CRC-32 calculator and serializer.
  - `ESP32FrameParser`: In-memory chunk buffer re-assembler, runaway delimiter-less buffer protector, sequence monotonicity tracker, port-to-device resolver, and `TelemetryValidator` integration.
  - `SyntheticESP32Source`: Deterministic generator for test/simulation capable of creating compliant frames, arbitrarily chunked streams, CRC-corrupted frames, electrical spikes, and clock drift without physical hardware.
- **`trust_engine/audit.py`**:
  - Added `__bool__(self) -> bool: return True` to ensure empty `AuditLog` instances evaluate as truthy in boolean expressions, preventing Python's default `len(self) == 0` falsiness gotcha when checking `if audit_log is None:`.

### 4. Stage 6 Automated Test Suite (`tests/test_esp32_transport.py` — 22 tests)
1. `test_compute_frame_crc32_canonical_and_deterministic`: Proves key-ordering invariance in CRC digest.
2. `test_format_esp32_frame`: Verifies valid formatting with CRC-32 and trailing newline.
3. `test_parse_valid_frame_line`: Asserts extraction of `ESP32Frame` and `PhysicalTelemetry`.
4. `test_stream_chunking_arbitrary_sizes`: Splits frames into 5-byte chunks and asserts proper reassembly upon newline.
5. `test_multiple_frames_in_single_chunk`: Feeds 3 consecutive frames in one chunk; asserts all 3 parsed in sequence.
6. `test_crlf_and_lf_line_endings`: Verifies CRLF (`\r\n`) and LF (`\n`) handling and blank line skipping.
7. `test_corrupt_crc_rejected`: Asserts corrupted CRC-32 is rejected with `CRC_MISMATCH`.
8. `test_crc_disabled_mode`: Verifies frames without CRC are accepted when `require_crc=False`.
9. `test_malformed_json_rejected`: Asserts broken JSON triggers `MALFORMED_JSON`.
10. `test_unsupported_version_rejected`: Asserts protocol versions != 1 trigger `UNSUPPORTED_VERSION`.
11. `test_missing_required_fields_rejected`: Asserts missing current/voltage/timestamp triggers `MISSING_FIELD`.
12. `test_invalid_field_types_rejected`: Asserts booleans passed as floats trigger `INVALID_FIELD_TYPE`.
13. `test_nan_and_inf_rejected`: Asserts non-finite floats trigger `NON_FINITE_VALUE`.
14. `test_negative_timestamp_rejected`: Asserts `ts < 0` triggers `NEGATIVE_TIMESTAMP`.
15. `test_sequence_tracking_and_regression_detection`: Asserts sequence regression triggers `OUT_OF_SEQUENCE`.
16. `test_sequence_reset_on_reboot`: Verifies `reset_sequence()` allows new starting sequence counter.
17. `test_buffer_overflow_runaway_line`: Asserts oversized buffer (> 200 bytes) without newline discards data cleanly and recovers.
18. `test_device_resolution_via_registry`: Resolves missing `device_id` from `DeviceRegistry` by matching `physical_port`.
19. `test_device_resolution_via_port_map`: Resolves missing `device_id` from static port map.
20. `test_unmapped_port_triggers_error`: Asserts unmapped port triggers `UNMAPPED_PORT`.
21. `test_physical_bounds_violation_surfaced`: Asserts overvoltage (35V) triggers `VALIDATION_FAILED`.
22. `test_audit_logging_on_frame_errors`: Asserts corrupt frames emit `AuditEvent` with `TELEMETRY_INVALID` and transport reason code.

---

### 5. Repository Test Summary
- **Stage 1 (State & Registry):** 18 tests
- **Stage 2 (Telemetry Schemas & Validation):** 17 tests
- **Stage 3 (Policy & Engine):** 21 tests
- **Stage 4 (Audit, Simulation & Enforcement):** 14 tests
- **Stage 5 (Security Review & Invariants):** 5 tests
- **Stage 6 (ESP32 Transport & CRC Parser):** 22 tests
- **Total Tests:** **97 / 97 passing in 0.05s**.

---

## Stage 7: Adversarial Exploit Resistance & Malicious Negative Test Suite

### 1. Scope & Adversary Model
Stage 7 establishes a dedicated adversarial suite (`tests/test_adversarial_suite.py`) containing intentional negative test cases, exploit simulations, and proof assertions designed to test the system under hostile conditions:
- **Active Adversary Capabilities:** An attacker with control over rogue device firmware, raw socket packet generators, and physical dock access attempting to circumvent zero-trust admission, hijack device bindings, corrupt memory, or poison sensor metrics.
- **Fail-Safe Goal:** Proves the system fails cleanly, rejects attacks, emits security audit alarms, and does not crack under unexpected edge conditions.

### 2. Architectural Hardening Discovered & Applied
During Stage 7 test construction, a second instance of Python's `__len__` truthiness gotcha was identified:
- **`DeviceRegistry` Truthiness Hardening:** In `TrustEngine.__init__`, `self.registry = registry or DeviceRegistry()` evaluated to a *new* registry instance whenever an empty `DeviceRegistry` (`len == 0`) was passed. Added `def __bool__(self) -> bool: return True` to `DeviceRegistry` and changed `TrustEngine.__init__` to `self.registry = registry if registry is not None else DeviceRegistry()`.

### 3. Stage 7 Adversarial Test Cases (`tests/test_adversarial_suite.py` — 13 tests)
1. **`test_adversarial_self_signed_trusted_escalation` (ATTACK-01):**
   Rogue firmware claims `status=TRUSTED` during registration. Asserted that `DeviceRegistry.register()` overrides status to `QUARANTINED`.
2. **`test_adversarial_mac_spoofing_conflict` (ATTACK-02):**
   Adversary docks on Port 2 with cloned MAC address of legitimate Port 1 device. Asserted that policy evaluation outputs `REJECT` verdict and transitions device to `REJECTED`.
3. **`test_adversarial_duplicate_id_overwrite_attack` (ATTACK-03):**
   Adversary attempts to re-register `critical-infra-node` with attacker parameters. Asserted that `DuplicateDeviceError` is raised and existing record is protected.
4. **`test_adversarial_memory_tampering_defensive_copy` (ATTACK-04):**
   Attacker mutates `status` on returned `Device` object. Asserted that internal registry state remains `QUARANTINED` via defensive copying.
5. **`test_adversarial_command_injection_payloads` (ATTACK-05):**
   Injects shell syntax (`"; rm -rf / ; $(reboot)"`) and path traversal in identifiers. Proves inert handling and audit log redaction.
6. **`test_adversarial_nan_poisoning_bypass` (ATTACK-06):**
   Adversary injects IEEE 754 `NaN` voltage aiming to bypass comparison operators. Asserted that `TelemetryValidator` detects non-finite float and raises `TelemetryValidationError`.
7. **`test_adversarial_infinite_current_spike` (ATTACK-07):**
   Adversary injects `+inf` shunt current. Asserted that `TelemetryValidator` rejects non-finite float.
8. **`test_adversarial_time_travel_stale_replay` (ATTACK-08):**
   Replay attack with 1-hour stale timestamp. Asserted that freshness check fails.
9. **`test_adversarial_future_clock_skew_injection` (ATTACK-09):**
   Adversary sends timestamp from year 2099 (+100,000s). Asserted that future clock skew check fails.
10. **`test_adversarial_volumetric_overflow` (ATTACK-10):**
    Adversary sends 5 billion packets attempting integer overflow. Asserted that packet count bounds fail.
11. **`test_adversarial_lifecycle_leap_monitoring_unadmitted_device` (ATTACK-11):**
    Adversary attempts to call `evaluate_monitoring` directly on an unadmitted `QUARANTINED` device. Asserted that `ValueError` is raised.
12. **`test_adversarial_illegal_state_transition_attempt` (ATTACK-12):**
    Adversary attempts direct jump `ISOLATED -> TRUSTED`. Asserted that `IllegalStateTransitionError` is raised.
13. **`test_xfail_demonstrating_nan_is_strictly_not_accepted` (XFAIL-PROOF):**
    Intentional `@pytest.mark.xfail(strict=True)` proof test demonstrating that asserting `is_valid == True` on NaN telemetry fails. Proves the test suite strictly catches invalid states.

---

### 4. Repository Test Summary
- **Stage 1 (State & Registry):** 18 tests
- **Stage 2 (Telemetry Schemas & Validation):** 17 tests
- **Stage 3 (Policy & Engine):** 21 tests
- **Stage 4 (Audit, Simulation & Enforcement):** 14 tests
- **Stage 5 (Security Review & Invariants):** 5 tests
- **Stage 6 (ESP32 Transport & CRC Parser):** 22 tests
- **Stage 7 (Adversarial Exploit Resistance Suite):** 13 tests (12 passed, 1 xfailed)
- **Total Tests:** **110 tests across 12 test suites (109 passed, 1 xfailed in 0.06s)**.






