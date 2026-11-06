from backend.services import hindsight_service as hs

r = hs.recall_similar("encoded PowerShell on a workstation", tenant="seeded")
ids = sorted({i for m in r["memories"] for i in m["incident_ids"]})
print(r["status"], ids)