# CyberMemory AI — Frontend/Backend API Contract Specification
**Project:** CyberMemory AI (HackwithHyderabad 3.0 / Hindsight Hackathon)  
**Author:** Frontend & Dashboard Engineering  
**Target Backend:** Python Flask / FastAPI  
**Standard Format:** JSON (`application/json`)  
**Auth / Headers:** Standard Bearer / API token or session header where applicable.

---

## 1. Overview & Architecture

CyberMemory AI connects a modern SOC Dashboard frontend with an AI incident response and persistent Hindsight memory backend. This document defines the RESTful endpoints required by the frontend.

The frontend is architected to operate with:
1. **Live Backend API**: When the backend services are running.
2. **Local Fallback / Standalone Mode**: Seamlessly serves realistic mock responses when developing or demonstrating offline, preventing UI breakage if an external LLM/Hindsight service is briefly unreachable.

---

## 2. API Endpoints

### 2.1 Dashboard Summary
* **Endpoint:** `GET /api/dashboard/stats`
* **Description:** Returns high-level metrics for dashboard cards and charts.
* **Response Body (200 OK):**
```json
{
  "total_investigated": 24,
  "memory_items_stored": 19,
  "resolved_incidents": 21,
  "feedback_satisfaction_rate": 95.8,
  "severity_breakdown": {
    "Critical": 5,
    "High": 8,
    "Medium": 7,
    "Low": 4
  },
  "memory_growth": [
    {"date": "2026-11-01", "nodes": 4, "retrievals": 3},
    {"date": "2026-11-02", "nodes": 8, "retrievals": 11},
    {"date": "2026-11-03", "nodes": 12, "retrievals": 19},
    {"date": "2026-11-04", "nodes": 16, "retrievals": 28},
    {"date": "2026-11-05", "nodes": 19, "retrievals": 39}
  ],
  "system_status": {
    "hindsight_connected": true,
    "hindsight_bank": "cybermemory-soc-v1",
    "llm_engine": "groq-qwen3-32b",
    "active_nodes": 19
  }
}
```

---

### 2.2 Incident Investigation
* **Endpoint:** `POST /api/investigate`
* **Description:** Submits a security alert for LLM reasoning and Hindsight memory correlation.
* **Request Body:**
```json
{
  "title": "Suspicious PowerShell Execution",
  "alert_source": "CrowdStrike Falcon EDR",
  "severity": "High",
  "affected_host": "FIN-WKS-042",
  "user": "corp\\jdoe",
  "description": "powershell.exe spawned with base64 encoded payload",
  "raw_logs": "EventID: 4688 ...",
  "use_memory": true
}
```
* **Response Body (200 OK):**
```json
{
  "investigation_id": "INC-2026-0821",
  "timestamp": "2026-11-06T14:20:00Z",
  "incident_summary": "Observed execution of obfuscated PowerShell spawned by Excel attempting network C2 beaconing.",
  "suggested_severity": "High",
  "confidence_score": 0.94,
  "confidence_explanation": "High confidence based on exact match of known encoded downloader syntax and process parentage.",
  "extracted_iocs": {
    "ips": ["198.51.100.44"],
    "domains": ["c2.evildomain.xyz"],
    "hashes": ["7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"],
    "processes": ["EXCEL.EXE", "powershell.exe"],
    "mitre_techniques": ["T1059.001", "T1204.002", "T1071.001"]
  },
  "historical_memory_matches": [
    {
      "incident_id": "INC-2026-0801",
      "similarity_score": 0.92,
      "relevance_explanation": "Identical Excel-to-PowerShell execution chain with Base64 payload downloader.",
      "historical_root_cause": "Malicious macro in supplier invoice phishing email.",
      "historical_remediation": "EDR host isolation and perimeter domain sinkholing.",
      "lessons_learned": "Enforce strict Office macro-blocking via GPO."
    }
  ],
  "investigation_plan": [
    {
      "step": 1,
      "priority": "High",
      "action": "Decode Base64 payload and block external IP",
      "reason": "Sever active C2 channel",
      "evidence_to_collect": "PowerShell command line arguments",
      "expected_result": "Extracted staging URL c2.evildomain.xyz",
      "historical_reference": "INC-2026-0801"
    }
  ],
  "potential_root_causes": [
    "Spear-phishing attachment execution in user Outlook session",
    "Drive-by download through web browser zero-day"
  ],
  "recommended_containment": [
    "Execute network quarantine on FIN-WKS-042 via EDR",
    "Block IP 198.51.100.44 at corporate edge firewall",
    "Revoke Kerberos TGT and reset credentials for corp\\jdoe"
  ],
  "safety_notice": "Read-only SOC analysis mode: Actions require human analyst verification and authorization.",
  "memory_used": true
}
```

---

### 2.3 Retain Incident Feedback & Memory Learning
* **Endpoint:** `POST /api/investigation/{id}/feedback`
* **Description:** Records analyst feedback and retains the finalized outcome into Hindsight persistent memory.
* **Request Body:**
```json
{
  "rating": "Helpful", 
  "comments": "The suggested containment step stopped lateral movement immediately.",
  "final_outcome": "Confirmed Malicious",
  "root_cause_confirmed": "Spear-phishing invoice attachment",
  "analyst_id": "analyst_sec_01",
  "retain_to_hindsight": true
}
```
* **Response Body (200 OK):**
```json
{
  "status": "success",
  "hindsight_retained": true,
  "retained_memory_id": "mem_node_84920",
  "message": "Incident experience successfully retained into Hindsight memory bank 'cybermemory-soc-v1'."
}
```

---

### 2.4 Incident History
* **Endpoint:** `GET /api/incidents`
* **Query Parameters:**
  * `query`: Search string (title, IOC, host)
  * `severity`: `Critical` | `High` | `Medium` | `Low` | `all`
  * `type`: Incident category filter
  * `outcome`: `Confirmed Malicious` | `False Positive` | `all`
* **Response Body (200 OK):**
```json
{
  "total": 20,
  "incidents": [
    {
      "id": "INC-2026-0801",
      "timestamp": "2026-11-04T08:14:22Z",
      "title": "Suspicious Encoded PowerShell Execution...",
      "severity": "High",
      "affected_host": "FIN-WKS-042",
      "user": "corp\\jdoe",
      "alert_type": "Suspicious PowerShell execution",
      "final_outcome": "Confirmed Malicious",
      "analyst_feedback": {"rating": "Helpful"}
    }
  ]
}
```

---

### 2.5 Memory Explorer & Semantic Search
* **Endpoint:** `GET /api/memory/search`
* **Query Parameters:**
  * `q`: Natural language search query (e.g., `"powershell encoded download"`)
  * `limit`: Number of results (default: 10)
* **Response Body (200 OK):**
```json
{
  "query": "powershell encoded download",
  "total_matches": 3,
  "results": [
    {
      "memory_id": "mem_0801",
      "incident_id": "INC-2026-0801",
      "score": 0.94,
      "summary": "Excel spawning powershell with base64 download cradle to c2.evildomain.xyz",
      "proven_strategy": "Isolate host immediately, extract C2 domain, sinkhole at perimeter DNS",
      "feedback_score": 1.0,
      "retained_at": "2026-11-04T08:30:00Z"
    }
  ]
}
```

---

### 2.6 Learning Analytics
* **Endpoint:** `GET /api/analytics/learning`
* **Response Body (200 OK):**
```json
{
  "total_memories": 19,
  "retrieval_count": 87,
  "reuse_rate_percentage": 78.4,
  "avg_triage_time_without_memory_min": 38.5,
  "avg_triage_time_with_memory_min": 7.2,
  "satisfaction_trend": [
    {"week": "Week 1", "satisfaction_rate": 81.0, "retrievals": 12},
    {"week": "Week 2", "satisfaction_rate": 89.5, "retrievals": 34},
    {"week": "Week 3", "satisfaction_rate": 96.2, "retrievals": 87}
  ],
  "mitre_coverage": [
    {"technique": "T1059 (Execution)", "count": 6},
    {"technique": "T1110 (Brute Force)", "count": 3},
    {"technique": "T1486 (Ransomware)", "count": 2},
    {"technique": "T1078 (Valid Accounts)", "count": 3},
    {"technique": "T1190 (Exploit Public)", "count": 2},
    {"technique": "T1567 (Exfiltration)", "count": 2}
  ]
}
```

