# 3-Minute Video Demo Script & YouTube Package

## 5 High-Performing YouTube Titles
1. **I Built an AI SOC Analyst That Never Forgets an Intrusion**
2. **Why Stateless AI Sucks for Cybersecurity (And How Memory Fixes It)**
3. **Teaching AI Agents Long-Term Memory with Hindsight**
4. **Autonomous Incident Response with Persistent Memory (Before vs After)**
5. **How We Cut Security Incident Triage from 38 to 7 Minutes Using Agent Memory**

---

## 3-Minute Demo Script with Screen Cues

### Part 1: Quick Intro (0:00 – 0:30)
- **Visual Cue:** Show `http://localhost:5000` (The futuristic dark glassmorphism dashboard with 19 active memory nodes and the live telemetry clock).
- **Narration:**  
  *"Hey everyone. In security operations, triage speed is everything. But current LLM assistants have digital amnesia: they treat every alert as if it's the first time they've ever seen it. I'm part of the engineering team behind CyberMemory AI—an AI-powered SOC investigation assistant built with Vectorize Hindsight persistent memory. Unlike standard chatbots, CyberMemory AI remembers historical incidents, verified root causes, and analyst corrections across sessions."*

---

### Part 2: The Problem: Stateless Agent Failure (0:30 – 1:00)
- **Visual Cue:** Click **New Investigation** (`/investigate`). Click **"Demo 1: Encoded PowerShell"** preset. Toggle OFF *"Retrieve Hindsight Historical Context"*. Click **Run AI Investigation**.
- **Narration:**  
  *"Here’s what happens without memory. We submit a suspicious Base64 PowerShell execution spawned by an Office macro. Without memory, the AI has no context: it suggests generic steps like 'inspect host', doesn't recognize the C2 infrastructure, and has no idea this same technique targeted finance three days ago. Triage takes nearly 40 minutes because the analyst has to manually correlate every artifact."*

---

### Part 3: Live Demo: Hindsight Memory in Action (1:00 – 2:30)
- **Visual Cue 1:** Go back to `/investigate`. Toggle ON *"Retrieve Hindsight Historical Context"*. Click **Run AI Investigation**.
- **Visual Cue 2:** Show the 5-stage progress animation (*Parsing ➔ IOC Extraction ➔ Hindsight Memory Recall ➔ LLM Reasoning ➔ Report Synthesis*).
- **Visual Cue 3:** On the results page (`/investigation/<id>`), hover over the **Hindsight Memory Matches** card showing **92% match to INC-2026-0801**.
- **Narration:**  
  *"Now watch what happens when we enable Hindsight persistent memory. The agent queries memory bank `cybermemory-soc-v1`. It instantly recalls incident INC-2026-0801 with 92% similarity. Notice the immediate difference: instead of generic advice, it flags the exact weaponized invoice pattern, reveals the staging C2 domain, and references the exact GPO mitigation rule proven in the prior case. Triage drops from 38 minutes to just 7 minutes."*
- **Visual Cue 4:** Scroll down to **Analyst Feedback & Retention Loop**. Select **Helpful**, confirm **Confirmed Malicious**, and click **"Retain Experience to Hindsight"**.
- **Narration:**  
  *"And because memory is a two-way loop, once the analyst validates the finding, hitting 'Retain Experience' writes this new case back into Hindsight. The agent literally gets smarter with every single investigation."*

---

### Part 4: Wrap-Up & What Surprised Me (2:30 – 3:00)
- **Visual Cue:** Click **Memory Explorer** (`/memory`) and search `"powershell"`, then click **Learning Analytics** (`/analytics`) showing the **-81.3% MTTR reduction chart**.
- **Narration:**  
  *"What surprised me most about building with Hindsight is that memory isn't just a vector store—it fundamentally changes how LLMs reason. When an agent has access to past successful decisions, it stops hallucinating abstractions and starts delivering actionable runbooks. Check out the code and memory architecture in the repository linked below. Thanks for watching."*

---

## YouTube Thumbnail Prompt (for Google Nano Banana)
```text
Aspect Ratio: 16:9
Prompt: A futuristic, sleek cybersecurity operations command center with floating translucent purple and cyan glowing glass interface cards. In the center, an illuminated AI glowing core orb with neural memory pathways connecting to digital server nodes. Bold, readable neon typography in the upper corner: 'AI SOC ANALYST WITH MEMORY'. High contrast, cinematic dramatic rim lighting, photorealistic, Unreal Engine 5 aesthetic, no clutter.
```
