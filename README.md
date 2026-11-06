# CyberMemory AI — Incident Investigation Assistant with Persistent Memory

> **HackwithHyderabad 3.0 AI Agents Hackathon Project**  
> AI-Powered Cybersecurity Incident Response with Vectorize Hindsight Memory  
> **Git Branch**: `security-and-deployment`  
> **Author & Lead**: Data, Security & Testing Engineer (`netwrkspider.org`)

---

## 🛡️ Project Overview

CyberMemory AI is an AI-powered cybersecurity system that investigates security threats, identifies root causes, and recommends solutions. Using persistent Hindsight memory, it learns from past incidents and analyst feedback to deliver smarter, context-aware security recommendations.

Traditional cybersecurity AI chatbots suffer from **investigator amnesia**: every alert begins from scratch, ignoring past root causes, confirmed malicious indicators, and proven remediation steps. CyberMemory AI bridges this gap as an intelligent SOC Tier 3 investigation assistant that remembers historical security incidents, investigation procedures, root causes, remediation actions, analyst feedback, and final outcomes.

### Core Capabilities
* **Persistent Incident Memory**: Stores incident experiences using Hindsight (`retain`, `recall`, `reflect`).
* **Cold-Start Transparency**: Explicitly alerts analysts when running without historical context; never fabricates past cases.
* **Warm-Memory Fast-Tracking**: Automatically recalls ancestral incident cases, pre-populating triage plans with historically verified remediation actions.
* **Strict Read-Only Analysis Mode**: Guarantees zero execution of commands extracted from reports and enforces human-in-the-loop signoff on all containment suggestions.
* **Defensive Prompt-Injection Shield**: Defangs adversarial payloads injected into security logs and headers.

---

## 🏗️ System Architecture

```
cybermemory/
├── data/
│   ├── synthetic_incidents.json        # 22 realistic incidents across 10 threat types
│   └── test_payloads/                  # Clean, adversarial, and corrupted test cases
├── cybermemory/
│   ├── models.py                       # Dataclasses & schema models
│   ├── data_loader.py                  # Dataset loader, query engine & validator
│   ├── security/                       # Security & safety guardrails
│   │   ├── sanitizer.py                # Schema validation & file upload restrictions
│   │   ├── prompt_injection.py         # Multi-layer prompt injection defanger
│   │   ├── redactor.py                 # Safe logging & secret scrubber
│   │   └── policy_guard.py             # READ_ONLY_ANALYSIS invariant enforcement
│   ├── memory/                         # Hindsight memory subsystem
│   │   ├── hindsight_service.py        # Official SDK wrapper (Retain/Recall/Reflect)
│   │   └── memory_mock.py              # In-memory/disk deterministic test mock
│   ├── agent/                          # Investigation & reasoning engine
│   │   ├── indicator_extractor.py      # High-fidelity regex & IOC extractor
│   │   ├── prompt_templates.py         # Guardrailed prompt boundaries
│   │   └── investigator.py             # Alert lifecycle orchestrator
│   └── api/
│       └── app.py                      # Production Flask REST API
├── tests/                              # Automated test suite (19 test cases)
│   ├── test_empty_memory.py
│   ├── test_incident_ingestion.py
│   ├── test_memory_retrieval.py
│   ├── test_memory_populated_investigation.py
│   ├── test_analyst_feedback.py
│   ├── test_persistence.py
│   ├── test_irrelevant_memories.py
│   ├── test_incorrect_history.py
│   ├── test_api_failures.py
│   ├── test_prompt_injection.py
│   └── test_before_after_eval.py       # Quantitative benchmark evaluation
├── docs/                               # Project documentation
│   ├── ARCHITECTURE.md                 # Detailed architecture & sequence flow
│   ├── SECURITY_AUDIT.md               # 9-point security compliance report
│   ├── TEST_REPORT.md                  # Comprehensive test execution logs
│   └── DEMO_GUIDE.md                   # 5-step live demonstration script
└── content/                            # Hackathon Content Guide deliverables
    ├── article.md                      # Technical publication article (1,200 words)
    ├── social_post.md                  # LinkedIn post (<800 chars, Karpathy style)
    └── video_script.md                 # 3-minute video walkthrough script
```

---

## ⚡ Quickstart & Installation

### 1. Clone & Checkout Branch
```bash
git clone https://github.com/manvithagowda/hackwme1.0.git
cd hackwme1.0
git checkout feature/data-testing
```

### 2. Set Up Virtual Environment & Dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure Environment Variables
```bash
cp .env.example .env
# Edit .env with your GROQ_API_KEY and HINDSIGHT_API_KEY
```

---

## 🧪 Running the Automated Test Suite

The test suite runs with zero mandatory third-party dependencies using Python's built-in `unittest` runner (also 100% compatible with `pytest`):

```bash
# Run all 19 tests across all 11 test modules:
python3 -m unittest discover -s tests -p "test_*.py" -v

# Or run using pytest:
pytest tests/ -v
```

### Real Test Execution Results (100% Pass Rate):
```
Ran 19 tests in 0.021s

OK
```

### Run the Comparative Benchmark:
```bash
python3 -m unittest tests/test_before_after_eval.py -v
```
**Benchmark Results**:
* **Recommendation Relevance**: Jumped from `0.00` to `1.00` (+1.00)
* **Evidence Coverage**: Increased from `0.50` to `1.00` (+0.50)
* **Historical Retrieval Precision**: Increased from `0.00` to `1.00` (+1.00)
* **Consistency Score**: Maintained at `1.00`

---

## 🚀 Running the Backend Service

### Local Flask Server
```bash
python3 -m cybermemory.api.app
# Server listens on http://localhost:5000
```

### API Endpoints
* `GET /api/health` — Service health, memory bank status, operational mode.
* `POST /api/investigate` — Submit security alert, retrieve memory, generate report.
* `POST /api/feedback` — Submit analyst feedback, retain outcome in Hindsight.
* `GET /api/incidents` — Query synthetic dataset with filtering by type, severity, or text.
* `POST /api/memory/seed` — Seed Hindsight memory bank with the 22 synthetic incidents.
* `POST /api/upload` — Secure file upload endpoint with size & magic byte validation.

### Docker Deployment
```bash
# Run multi-container stack (CyberMemory API + Hindsight Memory)
docker-compose up --build -d
```

---

## 📊 Synthetic Incident Dataset (22 Records)

The synthetic dataset in `data/synthetic_incidents.json` covers all 10 mandated cybersecurity threat categories:
1. **Suspicious PowerShell Execution** (`INC-2026-0001`, `INC-2026-0011`, `INC-2026-0021`)
2. **Phishing & Malicious Attachments** (`INC-2026-0002`, `INC-2026-0012`)
3. **Ransomware Behaviour** (`INC-2026-0003`, `INC-2026-0013`)
4. **Brute-Force Login Attempts** (`INC-2026-0004`, `INC-2026-0014`)
5. **Suspicious Outbound Connections** (`INC-2026-0005`, `INC-2026-0015`)
6. **Malware Persistence** (`INC-2026-0006`, `INC-2026-0016`)
7. **Privilege Escalation** (`INC-2026-0007`, `INC-2026-0017`)
8. **Unusual Account Activity** (`INC-2026-0008`, `INC-2026-0018`)
9. **Data Exfiltration** (`INC-2026-0009`, `INC-2026-0019`)
10. **Web Server Compromise** (`INC-2026-0010`, `INC-2026-0020`)
11. **Adversarial & Conflict Test Cases** (`INC-2026-0022`)

---

## 🔒 Security Posture & Guardrails

* **Zero Command Execution**: Prevents autonomous execution of any command parsed from reports.
* **Human-in-the-Loop Containment**: Every recommended action is marked `[RECOMMENDATION ONLY - REQUIRES HUMAN AUTHORIZATION]`.
* **Prompt Injection Defanging**: Malicious instructions in logs are neutralized before LLM reasoning.
* **Safe Error Logging**: Automatic redaction of API keys, passwords, and tokens.
* See [docs/SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md) for full compliance verification.
