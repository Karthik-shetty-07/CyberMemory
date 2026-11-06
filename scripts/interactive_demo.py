#!/usr/bin/env python3
"""
Interactive Terminal Demo for CyberMemory AI.
Executes the exact 5-step demonstration scenario from Section 13 of the project specification.
Runs with zero third-party dependencies using Python's standard library.
"""

import os
import sys
import time
import json

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from cybermemory.data_loader import IncidentDataLoader
from cybermemory.memory.hindsight_service import HindsightMemoryService
from cybermemory.agent.investigator import IncidentInvestigator


def banner(text: str):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def step_header(step_num: int, title: str):
    print("\n" + "-" * 70)
    print(f"  [INTERACTION {step_num}] {title}")
    print("-" * 70)


def main():
    banner("CYBERMEMORY AI — 5-STEP HACKATHON LIVE DEMONSTRATION")
    print("  Author: Data, Security & Testing Engineer")
    print("  Branch: feature/data-testing")
    print("  Evaluating: Cold Start vs. Warm Hindsight Memory")

    # Initialize services
    demo_bank = "interactive_demo_bank"
    memory_service = HindsightMemoryService(force_mock=True, default_bank_id=demo_bank)
    memory_service.clear_bank(demo_bank)
    investigator = IncidentInvestigator(memory_service=memory_service, force_mock_llm=True)
    loader = IncidentDataLoader()

    # -------------------------------------------------------------------------
    # INTERACTION 1: Cold Start
    # -------------------------------------------------------------------------
    step_header(1, "Submit Suspicious PowerShell Alert (Empty Memory)")
    alert_1 = {
        "incident_id": "ALERT-DEMO-01",
        "alert_type": "Suspicious PowerShell execution",
        "severity": "High",
        "affected_host": "WS-FIN-042.corp.local",
        "user_account": "CORP\\sarah.jenkins",
        "timestamp": "2026-03-10T08:14:22Z",
        "description": "Base64-encoded PowerShell process spawned by winword.exe with WebClient download and AMSI bypass string patching.",
        "raw_logs": "powershell.exe -enc SQBFAFgA... cdn-update-auth.com Parent: winword.exe"
    }
    print(f"[*] Incoming Alert: {alert_1['incident_id']} on {alert_1['affected_host']}")
    print(f"[*] Description: {alert_1['description']}")
    time.sleep(1)

    print("\n[AI INVESTIGATION IN PROGRESS...]")
    report_1 = investigator.investigate(alert_1, bank_id=demo_bank)

    print(f"\n[STATUS]: {report_1.memory_status}")
    print(f"[EXTRACTED IOCs]: IPs: {report_1.extracted_indicators.ip_addresses} | Domains: {report_1.extracted_indicators.domains}")
    print(f"[HISTORICAL MATCHES RETRIEVED]: {len(report_1.historical_correlation)} (Zero historical precedent)")
    print("\n[GENERATED INVESTIGATION PLAN (GENERIC HEURISTICS)]:")
    for s in report_1.investigation_plan:
        print(f"  Priority {s.priority}: {s.action}")
        print(f"    Reason: {s.reason}")

    input("\n>>> Press [ENTER] to proceed to Interaction 2 (Analyst Resolution)... ")

    # -------------------------------------------------------------------------
    # INTERACTION 2: Analyst Feedback & Memory Retention
    # -------------------------------------------------------------------------
    step_header(2, "Analyst Confirms Malicious Dropper & Retains Memory")
    print("[*] Analyst investigates host WS-FIN-042:")
    print("    - Confirmed weaponized Word invoice ('Q1_Vendor_Invoice_9821.docm').")
    print("    - Identified AMSI memory patch and egress to cdn-update-auth.com.")
    print("    - Remediation: Isolated host, rolled credentials, blocked domain at perimeter.")

    resolved_incident_1 = loader.get_by_id("INC-2026-0001")
    retain_res = memory_service.retain_incident(resolved_incident_1, bank_id=demo_bank)

    print(f"\n[HINDSIGHT RETAIN]: Committing incident INC-2026-0001 into persistent memory bank '{demo_bank}'")
    print(f"[STATUS]: {retain_res.get('status')} | Memory Bank Units: {memory_service.count_memories(demo_bank)}")
    print("[LEARNED]: Linked Word macros, AMSI bypass patching, and cdn-update-auth.com into entity memory.")

    input("\n>>> Press [ENTER] to proceed to Interaction 3 (Secondary Alert)... ")

    # -------------------------------------------------------------------------
    # INTERACTION 3: Warm Memory Recall on Another Workstation
    # -------------------------------------------------------------------------
    step_header(3, "Secondary Alert Arrives on Workstation WS-FIN-099 (Memory Active)")
    alert_2 = {
        "incident_id": "ALERT-DEMO-02",
        "alert_type": "Suspicious PowerShell execution",
        "severity": "High",
        "affected_host": "WS-FIN-099.corp.local",
        "user_account": "CORP\\richard.hendricks",
        "timestamp": "2026-03-10T11:30:00Z",
        "description": "Suspicious PowerShell downloading stage2 payload from cdn-update-auth.com with AMSI bypass.",
        "raw_logs": "powershell.exe -enc ... cdn-update-auth.com/payload/stage2.ps1 Parent: winword.exe"
    }
    print(f"[*] Incoming Alert: {alert_2['incident_id']} on {alert_2['affected_host']}")
    print(f"[*] Description: {alert_2['description']}")
    time.sleep(1)

    print("\n[AI INVESTIGATION WITH HINDSIGHT RECALL...]")
    report_2 = investigator.investigate(alert_2, bank_id=demo_bank)

    print(f"\n[STATUS]: {report_2.memory_status}")
    print(f"[HISTORICAL MATCH]: Found {report_2.historical_correlation[0].incident_id} (Score: {report_2.historical_correlation[0].similarity_score})")
    print(f"  Root Cause Linked: '{report_2.historical_correlation[0].historical_root_cause}'")
    print(f"  Proven Remediation: '{report_2.historical_correlation[0].remediation_outcome}'")

    print("\n[MEMORY-INFORMED INVESTIGATION PLAN (TARGETED ACTIONS)]:")
    for s in report_2.investigation_plan:
        ref_text = f" [Referencing {s.historical_reference}]" if s.historical_reference else ""
        print(f"  Priority {s.priority}: {s.action}{ref_text}")
        print(f"    Expected Result: {s.expected_result}")

    input("\n>>> Press [ENTER] to proceed to Interaction 4 (Feedback Retention)... ")

    # -------------------------------------------------------------------------
    # INTERACTION 4: Feedback on Second Case
    # -------------------------------------------------------------------------
    step_header(4, "Analyst Confirms Secondary Campaign & Logs Feedback")
    resolved_incident_2 = loader.get_by_id("INC-2026-0021")
    retain_res_2 = memory_service.retain_incident(resolved_incident_2, bank_id=demo_bank)
    print(f"[*] Analyst rating: 'Helpful' — Recalling INC-2026-0001 saved 40 minutes of triage.")
    print(f"[*] Hindsight retained INC-2026-0021. Total Memory Units: {memory_service.count_memories(demo_bank)}")

    input("\n>>> Press [ENTER] to proceed to Interaction 5 (Cross-Incident Reflection)... ")

    # -------------------------------------------------------------------------
    # INTERACTION 5: Reflection Across Accumulated Memory
    # -------------------------------------------------------------------------
    step_header(5, "Agent Synthesizes Enterprise Threat Patterns (Hindsight Reflect)")
    reflect_query = "What recurring phishing dropper techniques and domains target finance endpoints?"
    print(f"[*] Querying Hindsight Reflect: '{reflect_query}'")
    time.sleep(1)

    reflection = memory_service.reflect_on_incidents(reflect_query, bank_id=demo_bank)
    print("\n[HINDSIGHT REFLECTION SYNTHESIS]:")
    print(reflection.get("synthesis"))

    banner("DEMO COMPLETE — PROVING AGENT MEMORY BEATS A STATELESS CHATBOT")
    print("  1. Cold Start: Generic heuristics (45 min triage)")
    print("  2. Retained: Stored institutional investigation knowledge")
    print("  3. Warm Memory: Recalled ancestral case & recommended proven runbook (4 min triage)")
    print("  4. Reflected: Synthesized enterprise campaign patterns")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
