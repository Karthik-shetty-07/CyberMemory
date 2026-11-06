"""
Test Case 6: Persistence across application restarts.
Verifies that memory banks and retained incident experiences survive process termination.
"""

import os
import tempfile
import unittest
from cybermemory.memory.hindsight_service import HindsightMemoryService


class TestPersistenceAcrossRestarts(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.persistence_path = os.path.join(self.temp_dir, "hindsight_test_store.json")
        self.test_bank = "persistent_tenant_bank"

    def tearDown(self):
        if os.path.exists(self.persistence_path):
            os.remove(self.persistence_path)
        if os.path.exists(self.temp_dir):
            os.rmdir(self.temp_dir)

    def test_memories_survive_service_restart(self):
        # Phase 1: Initialize service and retain incident
        service1 = HindsightMemoryService(
            force_mock=True,
            mock_persistence_file=self.persistence_path
        )
        sample = {
            "incident_id": "INC-PERSIST-100",
            "alert_type": "Data exfiltration",
            "description": "Mass file transfer via rclone to cloud storage.",
            "root_cause": "Compromised service account credentials.",
            "remediation": "Severed network switch ports, terminated rclone exfiltration processes, and reset passwords.",
            "final_outcome": "True Positive - Exfiltration Blocked",
            "analyst_feedback": {"rating": "Helpful", "comments": "Immediate block avoided compliance breach."},
            "lessons_learned": "Enforce egress restrictions on all database servers."
        }
        service1.retain_incident(sample, bank_id=self.test_bank)
        self.assertEqual(service1.count_memories(self.test_bank), 1)

        # Simulate full restart by destroying service1
        del service1

        # Phase 2: Start a brand-new service instance pointing to the same persisted storage
        service2 = HindsightMemoryService(
            force_mock=True,
            mock_persistence_file=self.persistence_path
        )

        # Verify that bank count is preserved
        self.assertEqual(service2.count_memories(self.test_bank), 1)

        # Verify that memory can be recalled accurately
        recalled = service2.recall_similar_incidents("rclone cloud exfiltration", bank_id=self.test_bank, top_k=1)
        self.assertEqual(len(recalled), 1)
        self.assertEqual(recalled[0].incident_id, "INC-PERSIST-100")
        self.assertIn("rclone", recalled[0].remediation_outcome.lower() + recalled[0].lessons_learned.lower() + recalled[0].historical_root_cause.lower())


if __name__ == "__main__":
    unittest.main()
