from backend import config
from backend.services import hindsight_service as hs

print("HEALTH:", hs.health())

inc = {"incident_id": "INC-002", "title": "Encoded PowerShell on WS-021",
       "alert_type": "powershell", "severity": "high", "host": "WS-021",
       "description": "Encoded PowerShell launched from a Word macro.",
       "iocs": ["185.220.101.5", "evil-cdn.example"],
       "steps": ["Isolate host", "Collect process tree"],
       "root_cause": "Phishing macro", "remediation": "Isolated host, reset credentials",
       "outcome": "Confirmed malicious", "feedback": "Helpful", "lessons": "Check macro-enabled attachments first"}
print("RETAIN:", hs.retain_incident(inc, tenant="test"))

r = hs.recall_similar("encoded PowerShell on a workstation", tenant="test")
print("RECALL:", r["status"], [m["incident_ids"] for m in r["memories"]])
print("REFLECT:", hs.reflect_lessons("What do we know about PowerShell incidents?", tenant="test")["text"][:200])

config.HINDSIGHT_URL = "http://localhost:1"
print("DOWN TEST:", hs.recall_similar("anything", tenant="test"))