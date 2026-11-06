# CyberMemory AI — Hackathon Live Demonstration Guide

This guide details the step-by-step walkthrough for the judges, exactly fulfilling Section 13 of the HackwithHyderabad 3.0 Project Specification.

---

## Demo Overview

* **Team**: CyberMemory AI (netwrkspider.org)
* **Value Proposition**: Transforming stateless AI into a SOC investigation partner that remembers past incident resolutions, accelerates triage, and prevents repetitive root-cause discovery.
* **Key Demo Moment**: Comparing the generic advice generated during **Interaction 1 (Cold Start)** with the fast, pinpoint root-cause correlation generated in **Interaction 3 & 5 (Warm Hindsight Memory)**.

---

## 5-Interaction Live Demo Script

### Interaction 1: Cold Start (The Problem of Amnesia)
* **Action**: In the UI (or API), submit initial alert `ALERT-DEMO-01` on host `WS-FIN-042`:
  * *Alert Type*: `Suspicious PowerShell execution`
  * *Description*: `Base64-encoded PowerShell process spawned by winword.exe with WebClient download and AMSI bypass string patching.`
* **What the Agent Displays**:
  * Status banner: `Cold Start (Empty Memory) - Running without historical context`.
  * Generates general, heuristic triage steps: check event logs, examine parent process, inspect network proxy.
  * Root causes marked as unconfirmed `[AI HYPOTHESIS]`.
* **Talking Point to Judges**:
  > "Notice how a standard, stateless LLM reacts to a novel alert: it gives sound but completely generic triage advice. It does not know whether this has happened before in our enterprise, what the dropper was, or how our team previously fixed it."

---

### Interaction 2: Analyst Resolution & Hindsight Retention
* **Action**: The analyst investigates endpoint `WS-FIN-042`, identifies weaponized Word attachment `Q1_Vendor_Invoice_9821.docm` calling `cdn-update-auth.com`, isolates the machine, updates Group Policy to block unverified macros, and submits feedback via the feedback form:
  * *Rating*: `Helpful`
  * *Actual Outcome*: `True Positive - Malicious Dropper Contained`
  * *Resolution Notes*: `Extracted AMSI memory patch; blocked domain cdn-update-auth.com at perimeter firewall.`
* **What Happens Under the Hood**:
  * System calls `memory_service.retain_incident(...)` storing incident `INC-2026-0001` into Hindsight persistent memory.
  * Hindsight creates semantic, entity, and temporal relationships linking Word macros, AMSI patching, and `cdn-update-auth.com`.
* **Talking Point to Judges**:
  > "In a traditional SOC, this investigation outcome is trapped in ticketing notes or forgotten. With CyberMemory AI, submitting analyst feedback automatically retains this institutional knowledge into persistent Hindsight memory."

---

### Interaction 3: Secondary Alert on Another Workstation (Memory in Action!)
* **Action**: 2 hours later, a new alert arrives from finance workstation `WS-FIN-099` (User: `richard.hendricks`):
  * *Alert Type*: `Suspicious PowerShell execution`
  * *Description*: `PowerShell script downloading stage2 payload from cdn-update-auth.com.`
* **What the Agent Displays**:
  * Status banner: `Active Memory (Retrieved past incident INC-2026-0001)`.
  * **Immediate Correlation**: Flags that `cdn-update-auth.com` and the AMSI bypass match the exact campaign seen earlier on `WS-FIN-042`.
  * **Memory-Informed Plan**: Instead of generic steps, Priority 1 immediately recommends checking for duplicate macro invoices and verifying if the perimeter firewall blocklist deployed in `INC-2026-0001` was effective.
  * Confidence increases from **65% to 92%**.
* **Talking Point to Judges**:
  > "Look at the dramatic difference! The agent didn't make the analyst reinvent the wheel. It recalled the previous incident from Hindsight, identified the common adversary infrastructure, and recommended the exact proven containment steps."

---

### Interaction 4: Continuous Learning & Feedback
* **Action**: Analyst completes triage on `WS-FIN-099`, verifies that the firewall block worked, and submits feedback:
  * *Rating*: `Helpful`
  * *Analyst Notes*: `Recalling INC-2026-0001 saved 40 minutes of root-cause analysis.`
* **What Happens**:
  * Hindsight retains `INC-2026-0021` as a confirmed child campaign of `INC-2026-0001`.

---

### Interaction 5: Reflection & Enterprise Pattern Synthesis
* **Action**: Analyst opens the **Memory Explorer / Learning Analytics** tab and queries:
  * *Query*: `What are the recurring phishing dropper techniques observed across finance endpoints?`
* **What Hindsight Reflect Produces**:
  * A synthesized multi-incident reflection combining `INC-2026-0001` and `INC-2026-0021`:
  * *Synthesis*: Identifies that finance workstations (`WS-FIN-*`) are repeatedly targeted via macro-enabled invoice attachments using AMSI memory bypasses. Recommends enterprise-wide deployment of Attack Surface Reduction (ASR) rule *'Block Office applications from creating child processes'*.
* **Talking Point to Judges**:
  > "This is the frontier of agentic memory: moving from one-shot search to reflection across multiple incidents. CyberMemory AI doesn't just remember individual tickets—it synthesizes enterprise threat patterns to recommend systemic security hardening."
