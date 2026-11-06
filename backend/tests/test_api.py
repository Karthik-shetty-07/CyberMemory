from backend.app import create_app

c = create_app().test_client()
H = {"X-Tenant-ID": "test"}

print("HEALTH:", c.get("/api/memory/health").get_json())

r = c.post("/api/memory/retain", headers=H, json={
    "incident_id": "INC-003", "title": "Brute force on VPN", "alert_type": "brute_force",
    "severity": "medium", "host": "VPN-GW-01",
    "description": "400 failed logins from one IP in 10 minutes, then one success.",
    "iocs": ["203.0.113.50"], "steps": ["Check auth logs", "Block source IP"],
    "root_cause": "Credential stuffing", "remediation": "Blocked IP, forced password reset",
    "outcome": "Confirmed malicious", "feedback": "Helpful", "lessons": "Enable lockout policy"})
print("RETAIN:", r.status_code, r.get_json())

r = c.post("/api/memory/recall", headers=H, json={"query": "many failed logins then a success"})
j = r.get_json()
print("RECALL:", r.status_code, j["status"], [m["incident_ids"] for m in j["memories"]])

r = c.post("/api/memory/reflect", headers=H, json={"query": "What attack patterns have we seen?"})
print("REFLECT:", r.status_code, r.get_json()["text"][:120])

print("BAD QUERY:", c.post("/api/memory/recall", headers=H, json={"query": ""}).status_code, "(expect 400)")
print("BAD ID:", c.post("/api/memory/retain", headers=H, json={"incident_id": "x", "description": "d"}).status_code, "(expect 400)")
print("BAD TENANT:", c.post("/api/memory/recall", headers={"X-Tenant-ID": "../x"}, json={"query": "a"}).status_code, "(expect 400)")