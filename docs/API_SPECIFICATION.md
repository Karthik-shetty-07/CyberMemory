# CyberMemory AI — API & Integration Specification

**Target Audience**: Team Members (Frontend Engineer, Backend/Memory Engineer, AI Agent Orchestrator)  
**Author**: Data, Security & Testing Engineer  
**Branch**: `feature/data-testing`  
**Base URL**: `http://localhost:5000` (or `http://cybermemory_api:5000` in Docker)  
**Operational Invariant**: `X-Operational-Mode: READ_ONLY_ANALYSIS`

---

## 1. Overview & Security Headers

All endpoints return JSON responses. Every outgoing response includes enterprise defensive security headers:

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
X-Operational-Mode: READ_ONLY_ANALYSIS
```

---

## 2. Endpoints Matrix

| Method | Endpoint | Description | Auth / Security |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/health` | Service health, memory bank count, and inference backend | Public |
| `POST` | `/api/investigate` | Submit security alert, recall memory, generate triage report | Input sanitized, injection defanged |
| `POST` | `/api/feedback` | Record analyst outcome and retain experience in Hindsight | Retained into memory bank |
| `GET` | `/api/incidents` | Query and filter the 22 synthetic incident records | Query params: `type`, `severity`, `q` |
| `GET` | `/api/incidents/<id>` | Fetch detailed incident record by ID | Schema validated |
| `POST` | `/api/memory/seed` | Ingest all 22 synthetic records into Hindsight memory | Bulk retain |
| `GET` | `/api/memory/stats` | Inspect memory bank counts and dataset distribution | Public |
| `POST` | `/api/upload` | Securely upload and validate log files | Magic byte & 5MB size checks |

---

## 3. Detailed Request & Response Schemas

### A. Health & System Posture (`GET /api/health`)

#### Response (`200 OK`):
```json
{
  "status": "healthy",
  "service": "CyberMemory AI Investigation Engine",
  "version": "1.0.0",
  "operational_mode": "READ_ONLY_ANALYSIS",
  "hindsight_connected": true,
  "memory_bank_count": 22,
  "llm_backend": "Groq API (openai/gpt-oss-120b)"
}
```

---

### B. Investigate Alert (`POST /api/investigate`)

Submits an incoming alert for automated triage, IOC extraction, Hindsight memory recall, and structured report synthesis.

#### Query Parameters:
* `bank_id` *(optional, string)*: Target Hindsight memory bank (default: `cybermemory_soc_demo`).

#### Request Body (`application/json`):
```json
{
  "incident_id": "ALERT-2026-0021",
  "alert_type": "Suspicious PowerShell execution",
  "severity": "High",
  "affected_host": "WS-FIN-099.corp.local",
  "user_account": "CORP\\richard.hendricks",
  "timestamp": "2026-03-17T03:10:00Z",
  "description": "Suspicious PowerShell execution on finance workstation WS-FIN-099 with Base64 encoded payload calling WebClient and attempting AMSI memory bypass, targeting cdn-update-auth.com.",
  "raw_logs": "powershell.exe -enc SQBFAFgA... cdn-update-auth.com/payload/stage2.ps1 Parent: winword.exe"
}
```

#### Response (`200 OK`):
```json
{
  "status": "success",
  "data": {
    "incident_id": "ALERT-2026-0021",
    "timestamp": "2026-03-17T03:10:00Z",
    "incident_summary": "[CONFIRMED OBSERVATION] Detected suspicious activity matching pattern 'Suspicious PowerShell execution' on host WS-FIN-099.corp.local affecting user account CORP\\richard.hendricks. [HISTORICAL CONTEXT] Highly correlated with past incident INC-2026-0001 (relevance score 0.88): Matched historical alert characteristics with similarity score 0.88.",
    "severity_assessment": "High",
    "severity_rationale": "Severity evaluated as High. Elevated confidence due to direct correlation with past incident INC-2026-0001 which was previously resolved as a confirmed threat.",
    "extracted_indicators": {
      "ip_addresses": ["185.220.101.5"],
      "domains": ["cdn-update-auth.com", "ws-fin-099.corp.local"],
      "urls": ["http://cdn-update-auth.com/payload/stage2.ps1"],
      "file_hashes": [],
      "process_names": ["powershell.exe", "winword.exe"],
      "file_paths": [],
      "registry_keys": [],
      "user_accounts": ["CORP\\richard.hendricks"],
      "hostnames": ["WS-FIN-099.corp.local"]
    },
    "historical_correlation": [
      {
        "incident_id": "INC-2026-0001",
        "similarity_score": 0.88,
        "relevance_explanation": "Matched historical alert characteristics with similarity score 0.88.",
        "historical_root_cause": "User opened a weaponized phishing email attachment ('Q1_Vendor_Invoice_9821.docm') which executed an obfuscated VBA macro spawning PowerShell.",
        "investigation_steps": [
          "Extracted encoded CLI string from EDR event and decoded Base64 payload revealing IEX WebClient download.",
          "Identified parent process winword.exe with active child powershell.exe bypasses."
        ],
        "remediation_outcome": "Host isolated via EDR. Blocked cdn-update-auth.com at perimeter firewall. Revoked user Kerberos session tokens and rotated credentials.",
        "lessons_learned": "Attackers frequently use AMSI memory patching prior to downloading second-stage DLLs."
      }
    ],
    "memory_status": "Active Memory (1 historical cases retrieved)",
    "investigation_plan": [
      {
        "priority": 1,
        "action": "Fast-track validation of parent process and memory bypass signatures identified in INC-2026-0001",
        "reason": "Historical precedent INC-2026-0001 demonstrated root cause: 'User opened a weaponized phishing email attachment...'",
        "evidence_to_collect": "EDR process tree memory dump and script-block telemetry (Event ID 4104)",
        "expected_result": "Confirm whether the same weaponized dropper or payload variant was used",
        "historical_reference": "INC-2026-0001"
      },
      {
        "priority": 2,
        "action": "Cross-verify IOC indicators against firewall blocklists deployed during INC-2026-0001",
        "reason": "Verify if threat actor reused infrastructure identified in INC-2026-0001",
        "evidence_to_collect": "Zeek / NetFlow egress logs and DNS sinkhole match counters",
        "expected_result": "Determine whether egress was automatically blocked or active",
        "historical_reference": "INC-2026-0001"
      }
    ],
    "potential_root_causes": [
      "[HISTORICAL CONTEXT] Direct correlation with INC-2026-0001: 'User opened a weaponized phishing email attachment...'",
      "[AI HYPOTHESIS] Secondary campaign or lateral propagation from identical adversary infrastructure targeting subnet WS-FIN."
    ],
    "recommended_containment": [
      "[RECOMMENDATION ONLY - REQUIRES HUMAN AUTHORIZATION] Execute established runbook from INC-2026-0001: Host isolated via EDR. Blocked cdn-update-auth.com at perimeter firewall.",
      "[RECOMMENDATION ONLY - REQUIRES HUMAN AUTHORIZATION] Isolate host WS-FIN-099.corp.local immediately and revoke session tokens for CORP\\richard.hendricks."
    ],
    "confidence_and_limitations": "Confidence is high (92%). Grounded by Hindsight memory retrieval of INC-2026-0001. Analyst must confirm whether host exhibits secondary persistence mechanisms before un-quarantine.",
    "operational_mode": "READ_ONLY_ANALYSIS",
    "contains_hypotheses": true
  }
}
```

---

### C. Record Feedback & Retain Experience (`POST /api/feedback`)

Submits human analyst validation on an investigation, immediately committing the confirmed root cause and outcome into Hindsight memory.

#### Request Body:
```json
{
  "incident_id": "ALERT-2026-0021",
  "rating": "Helpful",
  "actual_outcome": "True Positive - Correlated with Prior Campaign INC-2026-0001",
  "actual_root_cause": "Secondary victim opened duplicate malicious invoice from same phishing campaign.",
  "actual_remediation": "Host isolated and applied IOC blocklist from INC-2026-0001.",
  "comments": "Recalling INC-2026-0001 cut triage duration from 45 minutes to 4 minutes.",
  "lessons_learned": "When an initial phishing incident is identified, proactive sweeps of the entire subnet prevent secondary infections."
}
```

#### Response (`200 OK`):
```json
{
  "status": "success",
  "message": "Analyst feedback retained in Hindsight memory",
  "memory_result": {
    "status": "success",
    "memory_id": "mem_cybermemory_soc_demo_23_3a7b9c",
    "bank_id": "cybermemory_soc_demo"
  }
}
```

---

### D. File Upload & Validation (`POST /api/upload`)

Accepts a multipart file upload (`file=@log.txt`). Enforces:
* Maximum size: **5 MB**
* Whitelisted extensions: `.json`, `.log`, `.txt`, `.csv`
* Magic byte check: Blocks `MZ` (PE EXE/DLL), `\x7fELF`, and Mach-O binaries.

#### Response (`200 OK`):
```json
{
  "status": "success",
  "filename": "sysmon_powershell_dump.log",
  "size_bytes": 48210,
  "message": "File passed all security and content validation checks"
}
```

#### Error Response (`400 Bad Request`):
```json
{
  "status": "error",
  "message": "File rejected: Dangerous executable or binary format detected (Magic byte check: b'MZ')"
}
```

