# CyberMemory AI — 3-Minute Video Demo Script & Visual Cues

**Speaker**: Manvitha (Data, Security & Testing Engineer, CyberMemory AI)  
**Target Duration**: 3 Minutes (180 Seconds)  
**Tone**: Direct, conversational, technical, engineering-focused  

---

## 5 High-Performing YouTube Video Titles
1. **I Built a SOC Agent with Long-Term Memory (No More Repetitive Forensics)**
2. **Why Stateless AI Sucks at Incident Response (And How Hindsight Fixes It)**
3. **From 45 Minutes to 4 Minutes: AI Incident Response with Hindsight Memory**
4. **How We Solved Agentic Amnesia in Cybersecurity Triage**
5. **Building an AI Threat Hunter That Never Forgets a Malicious Domain**

---

## Video Script & On-Screen Production Cues

### Part 1: Quick Intro (0:00 – 0:30)
* **[Screen Cue]**: Camera on speaker or terminal showing `git status` on branch `feature/data-testing`, followed by opening `docs/ARCHITECTURE.md`.
* **[Spoken Narration]**:  
  > "Hi everyone, I'm Manvitha. In modern security operations centers, Tier 3 analysts suffer from what I call 'investigator amnesia.' Every time an alert arrives, traditional AI chatbots start from a blank slate. They have zero memory of what was investigated yesterday, what root causes were confirmed, or which firewall blocklists were deployed. We built **CyberMemory AI**, an incident response assistant powered by Vectorize's persistent memory system, Hindsight, designed to remember past investigations and make every future triage dramatically smarter."

---

### Part 2: The Problem — The Amnesiac Agent (0:30 – 1:00)
* **[Screen Cue]**: Split screen showing terminal running `python3 -m unittest tests/test_empty_memory.py -v`. Show the test output highlighting:  
  `status_before: Cold Start (Empty Memory) - Running without historical context`.
* **[Spoken Narration]**:  
  > "Here's the fundamental flaw with stateless LLMs. When a suspicious PowerShell alert hits an endpoint in finance, the agent has no memory. It generates boilerplate advice: 'inspect Event 4688 logs, check proxy traffic, review user accounts.' That's sound textbook advice, but it forces an analyst to spend forty-five minutes re-investigating ground zero. It doesn't know that two days ago, an identical obfuscated script was traced back to a specific weaponized vendor invoice."

---

### Part 3: Live Demo — Retain, Recall & The Before/After (1:00 – 2:30)
* **[Screen Cue 1] (1:00 – 1:30)**: Open `data/synthetic_incidents.json` and show incident `INC-2026-0001` with its root cause and remediation. Run `python3 -m unittest tests/test_incident_ingestion.py -v`.
* **[Spoken Narration]**:  
  > "First, the memory retention step. In `cybermemory/memory/hindsight_service.py`, whenever an analyst resolves an incident and logs feedback, we call `client.retain()`. This doesn't just store flat text—Hindsight indexes the parent Word process, the AMSI bypass signature, and the C2 domain `cdn-update-auth.com` into an entity graph."

* **[Screen Cue 2] (1:30 – 2:30)**: Run the comparative benchmark test live:  
  `python3 -m unittest tests/test_before_after_eval.py -v`  
  Highlight the terminal output showing the benchmark table with `Recommendation Relevance: 0.0 -> 1.0` and `Historical Retrieval Precision: 0.0 -> 1.0`.
* **[Spoken Narration]**:  
  > "Now watch what happens when a secondary alert hits another workstation, `WS-FIN-099`. Instead of a cold start, our agent triggers `client.recall()`. Immediately, it correlates the alert with `INC-2026-0001` with high similarity! Look at the investigation plan generated in `after_report`:  
  > Priority 1: Fast-track validation of the parent Word macro and AMSI memory dump from the previous incident.  
  > Priority 2: Verify the perimeter firewall blocklist deployed in `INC-2026-0001`.  
  > Our automated benchmark shows evidence coverage jumped from fifty percent to one hundred percent, cutting triage time down to under four minutes."

---

### Part 4: Key Takeaway & Security Guardrails (2:30 – 3:00)
* **[Screen Cue]**: Open `cybermemory/security/policy_guard.py` and run `python3 -m unittest tests/test_prompt_injection.py -v`. Show all green passes.
* **[Spoken Narration]**:  
  > "What surprised me most as the Security & Testing Engineer was how essential safety guardrails are when memory is involved. In `cybermemory/security/`, we implemented strict prompt injection defanging so attackers can't inject malicious overrides into incident logs, and our `PolicyGuard` enforces a strict read-only mode so the AI never runs unauthorized commands on endpoints. Long-term memory transforms AI from a generic chatbot into an irreplaceable SOC partner. Thanks for watching, and check out our repo for the complete test suite!"

---

## Google Nano Banana Viral Thumbnail Prompt

**Aspect Ratio**: `16:9`  
**Prompt text to paste into Nano Banana**:
> A high-tech, cinematic cybersecurity operations center (SOC) dashboard at night. In the center, a glowing split-screen visual comparison: on the left side, a dull red wireframe AI human silhouette labeled "Stateless AI (45 Min Triage)" surrounded by chaotic warning popups; on the right side, a sharp electric-cyan and deep blue AI neural network brain labeled "CyberMemory AI + Hindsight (4 Min Triage)" with clean green checkmarks and connected threat data nodes. Bold modern typography in the upper third reading: "AI AGENTS THAT NEVER FORGET". High contrast, professional enterprise aesthetic, 8K render, photorealistic lighting, 16:9 aspect ratio.

