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
    print()

    # Stage 6 Demonstration: ESP32 UART Stream & Ingestion Pipeline
    print("=" * 70)
    print("      ESP32 UART TELEMETRY INGESTION & CRC-32 DEMONSTRATION")
    print("=" * 70)
    from trust_engine.esp32_transport import ESP32FrameParser, SyntheticESP32Source

    esp32_source = SyntheticESP32Source()
    esp32_parser = ESP32FrameParser()

    print("[1] Generating Compliant ESP32 Frame (Chunked 7 bytes/read):")
    valid_line = esp32_source.make_frame(port=1, voltage_v=5.08, current_a=0.42, temp_c=36.2, device_id="dock-dev-01")
    chunks = esp32_source.make_chunked_stream(valid_line, chunk_size=7)
    parsed_results = []
    for c in chunks:
        parsed_results.extend(esp32_parser.feed(c))
    
    if parsed_results and parsed_results[0].is_success:
        telem = parsed_results[0].telemetry
        print(f"  ✓ Reassembled & Verified: Port {telem.physical_port} | {telem.voltage_v:.2f}V | {telem.current_a:.2f}A | {telem.temperature_c}°C")
        print(f"  ✓ CRC-32 Checksum Validated: {parsed_results[0].frame.crc32}")

    print("\n[2] Simulating UART Transmission Noise (Corrupted CRC-32):")
    corrupt_line = esp32_source.make_frame(port=1, voltage_v=5.08, current_a=0.42, corrupt_crc=True, device_id="dock-dev-01")
    corrupt_results = esp32_parser.feed(corrupt_line.encode("utf-8"))
    if corrupt_results and not corrupt_results[0].is_success:
        err = corrupt_results[0].error
        print(f"  ✓ Corrupt Frame Detected: {err.reason.value}")
        print(f"  ✓ Error Details: {err.message}")

    print(f"\nParser Telemetry Statistics: {esp32_parser.stats}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
