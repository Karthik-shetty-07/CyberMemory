from backend.app import create_app

c = create_app().test_client()
H = {"X-Tenant-ID": "test"}

r = c.get("/api/memory/incidents", headers=H)
j = r.get_json()
print("INCIDENTS:", r.status_code, j["count"], [i["incident_id"] for i in j["incidents"]])
print("FILTER medium:", [i["incident_id"] for i in c.get("/api/memory/incidents?severity=medium", headers=H).get_json()["incidents"]])
print("DETAIL INC-003:", c.get("/api/memory/incidents/INC-003", headers=H).status_code)
print("DETAIL missing:", c.get("/api/memory/incidents/INC-999", headers=H).status_code, "(expect 404)")