#!/usr/bin/env python3
"""
Seed script to ingest the 22 synthetic incident records into Vectorize Hindsight memory.
"""

import sys
import os

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from cybermemory.data_loader import IncidentDataLoader
from cybermemory.memory.hindsight_service import HindsightMemoryService


def seed(bank_id: str = "cybermemory_soc_demo", force_mock: bool = False):
    print(f"[*] Initializing Hindsight Memory Service (Target Bank: '{bank_id}')...")
    service = HindsightMemoryService(default_bank_id=bank_id, force_mock=force_mock)
    loader = IncidentDataLoader()
    all_incidents = loader.get_all()

    print(f"[*] Loaded {len(all_incidents)} synthetic incident records from dataset.")
    print(f"[*] Live Hindsight Connected: {service.is_live}")

    count = 0
    for inc in all_incidents:
        inc_id = inc.get("incident_id")
        alert_type = inc.get("alert_type")
        res = service.retain_incident(inc, bank_id=bank_id)
        mode = res.get("mode", "retained")
        print(f"  [+] Retained {inc_id} ({alert_type}) -> [{mode}]")
        count += 1

    print("\n" + "=" * 60)
    print(f"[SUCCESS] Ingested {count} incident memories into bank '{bank_id}'")
    print(f"Total Bank Memory Units: {service.count_memories(bank_id)}")
    print("=" * 60)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "cybermemory_soc_demo"
    seed(bank_id=target)

