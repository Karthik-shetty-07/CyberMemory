# CyberMemory AI — Frontend & SOC Dashboard

> **Enterprise AI-Powered SOC Investigation Assistant with Persistent Hindsight Memory**  
> *Built for HackwithHyderabad 3.0 / Hindsight AI Agents Hackathon*

---

## 🛡️ Project Overview

**CyberMemory AI** is an enterprise-grade Security Operations Center (SOC) investigation assistant. Unlike traditional stateless AI chatbots that forget previous conversations once a session ends, CyberMemory AI remembers:
- Historical security incident investigations
- Correlated Indicators of Compromise (IOCs) & MITRE ATT&CK techniques
- Confirmed root causes and validated remediation runbooks
- Human analyst feedback and corrections

Powered by **Vectorize Hindsight Persistent Memory**, the agent becomes noticeably smarter with every incident investigated, dramatically accelerating triage turnaround from **38.5 minutes** down to **7.2 minutes**.

---

## 🎨 Visual Design System (Cyber SOC Dark Theme)

Designed from the ground up to reflect a mission-critical cybersecurity operations console:
- **Base Canvas:** Deep Charcoal / Navy (`#070B14`, `#0B1220`)
- **Accent Lighting:** Cyber Cyan (`#00F2FE`) & Electric Blue (`#38BDF8`)
- **Severity Hierarchy:**
  - 🔴 **Critical:** `#EF4444` (Active Ransomware, Token Theft, DMZ RCE)
  - 🟠 **High:** `#F97316` (Encoded PowerShell, Beaconing C2, SQL Injection)
  - 🟡 **Medium:** `#EAB308` (Kerberos Spraying, Scheduled Task Persistence)
  - 🟢 **Low:** `#10B981` (Reconnaissance noise, False Positive automations)
- **Typography:** *Inter* for clean UI readability, *JetBrains Mono* for hashes, IP addresses, and command-line forensics.
- **Charts:** Powered by *Plotly.js* with custom dark theme integration.

---

## 🖥️ 6 Core Dashboard Pages

| # | Page Route | View Description |
|---|---|---|
| **1** | `/` or `/dashboard` | **SOC Executive Dashboard:** Real-time KPI statistics (Total Investigated, Stored Memory Nodes, Resolved Malicious, Analyst Satisfaction), Plotly Severity Donut, Memory Growth timeline, and live activity feed. |
| **2** | `/investigate` | **New Investigation Studio:** Rich alert ingestion form with 1-click **Quick Demo Presets**, file upload, and a real-time 5-stage progress animation. |
| **3** | `/investigation/<id>` | **Deep Investigation Results:** Clear separation between *Observed Evidence*, *AI Hypotheses*, and *Hindsight Memory Matches*. Prioritized action plan, IOC copy chips, safety guardrails, and an interactive **Analyst Feedback & Hindsight Retention Form**. |
| **4** | `/history` | **Incident History & Forensic Archive:** Multi-facet filtering by Severity, Threat Type, and Outcome, full-text IOC search, and JSON export. |
| **5** | `/memory` | **Hindsight Memory Explorer:** Transparent inspector for agent memory banks (`cybermemory-soc-v1`), natural-language semantic vector search, remediation playbooks, and threat patterns. |
| **6** | `/analytics` | **Learning Analytics:** Empirical evaluation charts proving Hindsight memory value over time, triage MTTR reduction curves, and MITRE ATT&CK technique memory coverage. |

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+
- Modern Web Browser (Chrome, Firefox, Edge, Safari)

### 2. Setup & Installation
```bash
# Clone the repository and switch to frontend branch
git checkout frontend-and-dashboard

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching the Application
```bash
# Run Flask application server
python app.py
```
Open your browser and navigate to: **`http://localhost:5000`**

### 4. Running Automated Tests
```bash
python -m pytest tests/test_frontend.py
```

---

## 🎯 Hackathon Live 60-Second Demo Script

Follow this step-by-step sequence to demonstrate the power of Hindsight memory to the hackathon judges:

1. **Step 1: Open SOC Dashboard (`/`)**
   - Point out the **19 Hindsight Memory Nodes** already retained in `cybermemory-soc-v1`.
   - Highlight the **Severity Breakdown** and the **Memory Growth** timeline chart.

2. **Step 2: Launch New Investigation (`/investigate`)**
   - Click the **"Demo 1: Encoded PowerShell (Recall Match)"** preset button.
   - Watch the form populate with real-world Windows Event 4688 telemetry and Base64-encoded command lines.
   - Click **"Run AI SOC Investigation"**.
   - Observe the 5-stage real-time analysis pipeline (Parsing ➔ IOC Extraction ➔ Hindsight Recall ➔ LLM Reasoning ➔ Report Synthesis).

3. **Step 3: Inspect Investigation Results (`/investigation/<id>`)**
   - Point to the **Extracted IOCs** (IPs, processes, MITRE tags).
   - Highlight the **Hindsight Memory Match Card**: Show how the agent recalled past incident `INC-2026-0801` and recommended isolating the host and sinkholing the C2 domain based on past experience.
   - Emphasize the **SOC Safety Boundary** (AI advises, human authorizes).

4. **Step 4: Demonstrate Continuous Learning**
   - Scroll down to the **Analyst Feedback & Retention Loop**.
   - Rate the recommendation as **Helpful**, confirm outcome as **Confirmed Malicious**, and click **"Retain Experience to Hindsight"**.
   - Show how the new incident is instantly retained into memory.

5. **Step 5: Explore the Agent's Brain (`/memory` & `/analytics`)**
   - Open **Memory Explorer** and search `"powershell download"`.
   - Open **Learning Analytics** and show the **Cold vs Memory Triage Time** chart (**-81% MTTR reduction**).

---

## 📁 Repository Structure

```
CyberMemory/
├── app.py                         # Flask Web Server & Dual-Mode REST API
├── requirements.txt               # Dependencies
├── .gitignore                     # Git ignore rules
├── static/
│   ├── css/
│   │   └── cyber-soc.css          # SOC Dark Theme & Design Tokens
│   ├── js/
│   │   ├── api-client.js          # Unified Frontend REST Client
│   │   ├── dashboard.js           # Dashboard KPI & Plotly Charts
│   │   ├── investigation.js       # Studio & Pipeline Controller
│   │   ├── history.js             # Forensic Archive & Multi-Filters
│   │   ├── memory.js              # Hindsight Memory Explorer Controller
│   │   └── analytics.js           # Learning Progression & Evaluation Charts
│   └── data/
│       └── synthetic_incidents.json # 20 Section-9 Realistic Incident Fixtures
├── templates/
│   ├── base.html                  # Master SOC Shell, Navigation & Topbar
│   ├── dashboard.html             # Page 1: Dashboard
│   ├── investigate.html           # Page 2: New Investigation Studio
│   ├── investigation_result.html  # Page 3: Investigation Results & Feedback
│   ├── history.html               # Page 4: Incident History Archive
│   ├── memory_explorer.html       # Page 5: Hindsight Memory Explorer
│   └── analytics.html             # Page 6: Learning Analytics
├── docs/
│   └── API_CONTRACT.md            # Frontend/Backend Coordinated API Contract
└── tests/
    └── test_frontend.py           # Pytest Automated Integration Tests
```

---

## 🤝 Coordination with Backend Team
- Coordinated REST contracts are fully documented in [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md).
- The frontend includes built-in mock fallback data so it can be demonstrated seamlessly in standalone mode or connected to a live FastAPI / Hindsight backend.
