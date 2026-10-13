#!/usr/bin/env python3
"""Smart Backplane Trust Engine --- Demonstration CLI.

Runs deterministic demonstration scenarios on Raspberry Pi 3B+:
1. Normal Admission: Quarantine -> Compliant Telemetry -> TRUSTED.
2. Insufficient Evidence: Quarantine -> Incomplete Telemetry -> Remains QUARANTINED.
3. Policy Violation: Admitted -> C2 Traffic Detected -> ISOLATED -> Simulated Enforcement.

SAFETY NOTICE:
    All enforcement actions in this prototype are SIMULATED in-memory.
    NO Linux firewall rules, iptables commands, or GPIO pin switching are executed.
"""

import sys
from trust_engine.simulator import Simulator


def main() -> int:
    """Execute all Trust Engine demonstration scenarios and print results."""
    print("=" * 70)
    print("      SMART BACKPLANE TRUST ENGINE --- SCENARIO SIMULATOR")
    print("=" * 70)
    print("SAFETY DISCLAIMER: All enforcement actions are SIMULATION ONLY.")
    print("No hardware power lines, GPIO pins, or network firewall rules are changed.\n")

    simulator = Simulator()
    results = simulator.run_all()

    for idx, r in enumerate(results, 1):
        print(f"Scenario {idx}: {r.scenario_name}")
        print("-" * 50)
        print(f"  Device ID:         {r.device_id}")
        print(f"  State Transition:  {r.initial_state.value} -> {r.final_state.value}")
        print(f"  Verdict:           {r.decision.decision_type.value}")
        print(f"  Reason Code(s):    {', '.join(r.decision.reason_codes)}")
        print(f"  Explanation:       {r.decision.explanation}")

        if r.enforcement_result:
            enf = r.enforcement_result
            status_str = "SUCCESS (SIMULATED)" if enf.success else "FAILED"
            print(f"  Enforcement:       {enf.action.value} [{status_str}]")
            print(f"  Enforcement Note:  {enf.reason}")

        print(f"  Audit Trail:       {r.audit_event_count} events recorded")
        print(f"  Summary:           {r.summary}")
        print()

    print("=" * 70)
    print("All scenarios completed successfully with full deterministic audit trails.")
    print("Total Audit Events in Log:", len(simulator.audit_log))
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
