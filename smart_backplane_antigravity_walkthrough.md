# Smart Backplane Trust Engine --- Antigravity Build Walkthrough

**Goal:** Build a testable Python prototype in four stages. Antigravity
should implement one stage per prompt; review the diff and run tests
before proceeding.

**Target:** Raspberry Pi 3B+ running Raspberry Pi OS/Debian. Use Python
3 and `pytest`. Develop locally if convenient, then transfer/run on the
Pi through Raspberry Pi Connect.

## 1. What the software does

The Smart Backplane admits and monitors devices connected to physical
dock ports. New devices begin quarantined. The Raspberry Pi Trust Engine
owns the registry and trust decisions, evaluates physical and network
telemetry, records explanations, and requests enforcement actions.

The first version should demonstrate this flow:

1.  Register/observe a device.
2.  Put it in quarantine.
3.  Validate simulated physical and network telemetry.
4.  Apply explicit, explainable rules.
5.  Produce a decision with reason codes.
6.  Record a simulated action such as isolation.

### Honest scope

The prototype can demonstrate registry integrity, state transitions,
telemetry validation, rule-based decisions, audit events, and simulated
enforcement.

Do **not** claim that: - A MAC address proves identity. - Normal
power/network behaviour proves a device is genuine or uncompromised. - A
device-provided `"status": "trusted"` field grants trust. - The INA3221
provides power or switches ports; it only measures voltage/current. -
The Pi can inspect encrypted HTTPS application contents just because
traffic passes through it. - A Python service is protected against an
attacker with root access to the Pi. - A simulated isolation action
actually blocks traffic or cuts power.

Cryptographic device authentication, secure boot/attestation, hardened
OS configuration, and real network/power enforcement are later work
unless implemented and tested separately.

## 2. Architecture

``` text
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
                                      │
                         Later: firewall / ESP32

Dock power ── INA3221 monitor ── ESP32 ── telemetry to Pi
                     │
             measures up to 3 channels
```

The Pi can enforce network policy only if relevant traffic actually
passes through it. A state labelled `QUARANTINED` is not network
isolation until firewall/routing rules are configured and verified. Keep
enforcement simulated in this project phase.

### Component responsibilities

-   **Raspberry Pi / Trust Engine:** authoritative registry, state
    machine, policy evaluation, audit, enforcement requests.
-   **ESP32:** physical sensor readings and, later, carefully
    constrained power-switch control.
-   **INA3221:** voltage/current measurement; not a supply or switch.
-   **Enforcement adapter:** simulation now; separate Linux/ESP32
    adapters later.

## 3. State model

Use `DeviceState` (or consistently named `DeviceStatus`) with: -
`UNKNOWN` - `QUARANTINED` - `TRUSTED` - `ANOMALOUS` - `ISOLATED` -
`REJECTED`

Suggested transitions:

``` text
UNKNOWN -> QUARANTINED
QUARANTINED -> TRUSTED | REJECTED
TRUSTED -> ANOMALOUS
ANOMALOUS -> ISOLATED
ANOMALOUS -> TRUSTED       # only through an explicit recovery rule, if supported
ISOLATED -> QUARANTINED    # authorised recovery/revalidation
```

Centralise transition validation. Do not let arbitrary callers set any
state. A timeout can end an admission attempt, but it does not prove
malice; record a reason such as `admission_timeout`.

## 4. Repository layout

``` text
smart-backplane/
├── README.md
├── pyproject.toml or requirements-dev.txt
├── trust_engine/
│   ├── __init__.py
│   ├── states.py
│   ├── device.py
│   ├── registry.py
│   ├── telemetry.py
│   ├── policy.py
│   ├── engine.py
│   ├── audit.py
│   ├── enforcement.py
│   └── simulator.py
├── tests/
│   ├── test_states.py
│   ├── test_device.py
│   ├── test_registry.py
│   ├── test_telemetry.py
│   ├── test_policy.py
│   ├── test_engine.py
│   └── test_enforcement.py
└── main.py
```

Use dataclasses for records, enums for states, type hints,
standard-library logging, and `pytest`. No database, web framework,
dashboard, MQTT, ML, or real firewall/GPIO control in the first pass.

## 5. Data model and trust rules

### Device record

Include: - `device_id`: internal registry key. - `mac_address`: observed
identifier, not proof. - `physical_port`: dock port. - `ip_address`:
optional. - `status`: Trust Engine-owned state.

Optional timestamps and last-decision reason can be added if useful.
Per-device values must be instance fields, not shared class attributes.

### Registry

-   Map unique `device_id` values to device records.
-   Duplicate IDs must fail clearly and must never overwrite an existing
    record.
-   Flag unexpected MAC/port associations as conflicts.
-   A port is a location binding, not a secret credential.
-   Do not accept a device-supplied status as authoritative.
-   Define safe behaviour for missing IDs and duplicate observations.

### Telemetry

Keep physical and network telemetry as separate dataclasses.

**Physical:** port/device association, voltage (V), current (A),
timestamp, optional temperature (°C).

**Network:** observed source MAC/IP, destination, protocol, optional
ports, bytes/packets, timestamp/window.

Validate required fields, types, finite numeric values (reject
NaN/infinity), freshness, and configurable sensor bounds. Make units
explicit. Invalid input must not silently become trusted evidence.
Telemetry is evidence, not proof of identity.

## 6. Policy rules

Use deterministic, explainable rules---not ML or an opaque trust score.

The policy receives a device record and validated telemetry, then
returns a structured decision containing: - decision type: allow / keep
quarantined / reject / isolate; - reason codes and human-readable
explanation; - evidence summary; - recommended state/action.

Initial admission: 1. New device starts quarantined. 2. Validate schema
and freshness. 3. Check duplicate identity and MAC/port conflicts. 4.
Check whether minimum evidence has arrived. 5. Apply configured network
rules and physical ranges. 6. If evidence is insufficient, remain
quarantined until timeout. 7. If policy fails, reject or isolate
according to the explicit rule. 8. Only the Trust Engine can mark a
device trusted.

Initial monitoring: - Continue observing network metadata after
admission. - A mild, isolated anomaly should generally trigger more
observation, not automatic rejection. - Severe or repeated policy
violations can trigger restriction/isolation. - Keep identity confidence
separate from behavioural assessment. A valid identity does not mean
safe behaviour.

## 7. Enforcement and safety

Define a narrow interface, for example: -
`isolate_device(device_id, reason)` -
`restore_quarantine(device_id, reason)` -
`set_port_power(port, enabled, reason)` --- simulation only initially.

The simulation adapter records requested actions but does not change the
network or hardware. Policy code must not execute shell commands or
manipulate GPIO.

Before later real enforcement, verify in an isolated lab: - relevant
traffic passes through the Pi; - quarantine rules block only the
intended traffic; - Pi management access remains available; -
restart/recovery behaviour is safe; - invalid commands cannot
unexpectedly energise a port; - communication loss and adapter failures
have defined outcomes.

**Raspberry Pi Connect warning:** Do not experiment with firewall,
routing, DHCP, or interface configuration over your only remote
connection without a recovery path. A bad rule can disconnect you from
the Pi.

## 8. Audit log

Record discovery, registration success/failure, identity conflicts,
invalid telemetry, admission decisions, state transitions, enforcement
requests/results, and adapter failures. Use Python `logging` initially.
Include timestamps and reason codes; never log private keys or secrets.
A local log is not tamper-proof against root.

## 9. Tests by stage

Run tests after each stage and do not proceed until they pass.

### Stage 1 --- States and device model

-   Enum values and string conversion.
-   Two devices have independent statuses.
-   Invalid status conversion fails.
-   No shared mutable per-device state.

### Stage 2 --- Registry

-   Unique registration succeeds.
-   Duplicate ID fails without overwriting the original record.
-   Missing-ID lookup has defined behaviour.
-   MAC/port conflict is flagged.
-   Device-supplied `TRUSTED` cannot set registry status.

### Stage 3 --- Telemetry

-   Valid physical/network records accepted.
-   Missing fields and wrong types rejected.
-   Out-of-range values rejected.
-   NaN and infinity rejected.
-   Stale readings are not current evidence.
-   Optional network fields work correctly.

### Stage 4 --- Policy and engine

-   Insufficient evidence keeps device quarantined.
-   Passing defined requirements permits admission.
-   Identity conflict prevents admission.
-   Timeout has a clear reason.
-   Mild anomaly does not automatically reject.
-   Severe/repeated violation triggers expected restriction.
-   Illegal state transition is rejected.
-   Every decision includes reasons.

### Stage 5 --- Audit and simulation

-   Decisions/transitions create audit events.
-   Enforcement requests are recorded with device and reason.
-   Unknown device and invalid port fail safely.
-   Simulated adapter errors are surfaced.
-   No test invokes real firewall commands or GPIO.

### Stage 6 --- Later integration (not part of initial code generation)

-   Test ESP32 messages with synthetic data first.
-   Reject malformed or stale messages.
-   Observe network metadata without changing routes.
-   Test firewall rules in a disposable VM/isolated lab.
-   Verify Raspberry Pi Connect remains reachable.
-   Test low-voltage hardware separately before allowing software
    control.

## 10. Raspberry Pi setup

``` bash
mkdir -p ~/smart-backplane
cd ~/smart-backplane

python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install pytest
```

Run tests:

``` bash
python -m pytest -q
```

Run the simulator after tests pass:

``` bash
python main.py
```

Use Git if possible. Commit after each passing stage so you can roll
back.

## 11. Antigravity: four staged prompts

Use one prompt at a time. Inspect the diff and run tests yourself before
moving on. Do not ask Antigravity to generate the whole project in one
shot.

### Prompt 1 --- State model, Device, Registry

``` text
We are building the Smart Backplane Trust Engine in Python 3 for a Raspberry Pi 3B+.
Implement ONLY the state model, Device dataclass, and in-memory registry.

Create:
trust_engine/__init__.py
trust_engine/states.py
trust_engine/device.py
trust_engine/registry.py
tests/test_states.py
tests/test_device.py
tests/test_registry.py

Requirements:
- Define DeviceState with UNKNOWN, QUARANTINED, TRUSTED, ANOMALOUS,
  ISOLATED, REJECTED. Spell ANOMALOUS correctly.
- Use a dataclass for Device with device_id, mac_address, physical_port,
  optional ip_address, and status.
- Device fields must be per-instance, not shared class attributes.
- Trust status is owned by the engine/registry. Never trust a device-supplied
  status field or allow it to set itself TRUSTED.
- Registry is an in-memory mapping keyed by device_id.
- Duplicate IDs must fail clearly and never overwrite the existing record.
- Define missing-ID lookup behaviour.
- Add type hints and docstrings. Use standard-library application code only.
- Tests must cover enum conversion, independent state, registration,
  duplicate-ID rejection without overwrite, and missing lookup.
- Do not implement telemetry, policy, networking, firewall, GPIO, ESP32,
  database, or UI.

Run the tests. Show changed files, design decisions, and exact test command.
Stop after this stage.
```

**Checkpoint:** tests pass; inspect duplicate-ID handling.

### Prompt 2 --- Telemetry schemas and validation

``` text
Continue the existing repository. Implement ONLY telemetry models and validation.
Add trust_engine/telemetry.py and tests/test_telemetry.py.

Requirements:
- Separate PhysicalTelemetry and NetworkTelemetry dataclasses.
- Physical telemetry: port/device association, voltage in volts, current in
  amperes, timestamp, optional temperature in Celsius.
- Network telemetry: observed source MAC/IP, destination, protocol, optional
  ports, byte/packet counts, timestamp.
- Make optional fields explicit and units clear.
- Validate required fields, types, finite numbers, freshness, and configurable
  sensible bounds. Reject NaN and infinity.
- Invalid data must not silently become trusted evidence.
- Keep validation separate from policy decisions.
- Do not treat MAC or telemetry as proof of identity.
- Add tests for valid records, missing/wrong fields, invalid ranges, NaN/infinity,
  stale data, and optional network fields.
- Do not implement policy, network capture, firewall, GPIO, ESP32 transport,
  database, or UI.

Run the full test suite, fix regressions, list changed files and rules, then stop.
```

**Checkpoint:** old tests and telemetry tests all pass.

### Prompt 3 --- Policy and Trust Engine

``` text
Continue the existing repository. Implement ONLY deterministic policy evaluation
and Trust Engine orchestration. Add trust_engine/policy.py, trust_engine/engine.py,
and relevant tests.

Requirements:
- Use explicit, explainable rules, not ML or an opaque score.
- Input: Device record plus validated physical/network telemetry.
- Output: structured decision with decision type, reason codes, explanation,
  evidence summary, and recommended state/action.
- New devices start quarantined; insufficient evidence stays quarantined.
- Timeout ends the attempt with a clear reason; timeout alone is not proof of malice.
- Only the Trust Engine can transition a device to TRUSTED.
- Identity/port conflicts prevent automatic admission.
- One mild anomaly must not automatically reject a device.
- Define a simple, documented rule for severe or repeated network-policy violations.
- Keep identity confidence separate from behavioural assessment.
- Centralise and validate allowed state transitions.
- Every decision and transition must have a reason.
- Do not implement real network capture, firewall, GPIO, ESP32 transport,
  cryptographic authentication, database, or UI.

Tests must cover insufficient evidence, successful admission under the defined
rules, identity conflict, timeout, illegal transition, mild anomaly, and
severe/repeated violation. Run all tests, explain the rules, then stop.
```

**Checkpoint:** policy tests are deterministic and require no hardware.

### Prompt 4 --- Audit, simulator, simulated enforcement

``` text
Continue the existing repository. Implement ONLY audit logging, a deterministic
simulator, and a simulated enforcement adapter.

Create trust_engine/audit.py, trust_engine/enforcement.py,
trust_engine/simulator.py, main.py, relevant tests, and a concise README.

Requirements:
- Record discovery, registration conflicts, decisions, state transitions,
  enforcement requests/results, and adapter failures with timestamps/reason codes.
- Do not log secrets.
- Define a narrow enforcement interface for isolate, restore-to-quarantine,
  and requested port power changes.
- Simulation adapter records actions but performs NO real network or hardware
  changes. State this explicitly in output and documentation.
- Validate IDs, ports, and arguments; unknown devices/invalid ports fail safely.
- Simulator demonstrates normal admission, insufficient evidence/quarantine,
  and a policy violation/isolation.
- Tests cover audit events, recorded actions, invalid requests, adapter errors,
  and prove no real system command/GPIO operation occurs.
- Do not implement real firewall commands, route changes, GPIO, or ESP32 commands.
- README must include setup, test/run commands, and limitations.

Run `python -m pytest -q`, list changed files and remaining integration work, then stop.
```

**Checkpoint:** you can demonstrate the full decision path without
changing the Pi's network or dock power.

### Useful repair prompt

``` text
Do not add features or refactor unrelated files. Run the existing tests, identify
the first failure and its root cause, make the smallest appropriate fix, then
rerun the full test suite. Show the diff and explain the fix.
```

### Useful security-review prompt

``` text
Review only the latest stage. Do not rewrite the project. Identify correctness
and security issues involving trust-state authority, duplicate IDs, invalid or
stale telemetry, unsafe defaults, state transitions, shared mutable state, and
claims that exceed the code's actual guarantees. Rank findings by severity and
suggest minimal fixes.
```

## 12. Definition of done

-   [ ] Device registry works; duplicate IDs cannot overwrite records.
-   [ ] New devices enter quarantine.
-   [ ] Telemetry is validated before policy evaluation.
-   [ ] Decisions are deterministic and explainable.
-   [ ] Insufficient evidence remains quarantined.
-   [ ] A policy violation can trigger simulated isolation.
-   [ ] Decisions and transitions are audited with reasons.
-   [ ] `python -m pytest -q` passes.
-   [ ] README distinguishes simulated from real enforcement.
-   [ ] Demo does not risk the Pi's network connection or physical
    hardware.

**Build the smallest vertical slice first:** register → quarantine →
evaluate simulated evidence → decide → audit → simulate enforcement.
Only then integrate the ESP32, network observation, firewall, or power
switching.
