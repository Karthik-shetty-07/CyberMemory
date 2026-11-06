import argparse
import json
import os

from backend import db
from backend.services import hindsight_service as hs

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "incidents.json")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--tenant", default="seeded")
    a = p.parse_args()
    db.init_db()
    with open(DATA, encoding="utf-8") as f:
        incidents = json.load(f)
    for inc in incidents:
        existing = db.get_incident(a.tenant, inc["incident_id"])
        if existing and existing.get("hindsight_status") == "ok":
            print("skip", inc["incident_id"], "(already retained)")
            continue
        db.save_incident(a.tenant, inc, "pending")
        res = hs.retain_incident(inc, tenant=a.tenant)
        db.set_hindsight_status(a.tenant, inc["incident_id"], res["status"])
        print(inc["incident_id"], res["status"])


if __name__ == "__main__":
    main()