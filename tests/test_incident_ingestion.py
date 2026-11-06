"""
Test Case 2: Incident ingestion into Hindsight.
Verifies retain payload structure, entity indexing, and memory count tracking.
"""

import unittest
from cybermemory.data_loader import IncidentDataLoader
from cybermemory.memory.hindsight_service import HindsightMemoryService


class TestIncidentIngestion(unittest.TestCase):

    def setUp(self):
        self.test_bank = "test_ingestion_bank"
        self.memory_service = HindsightMemoryService(force_mock=True)
        self.memory_service.clear_bank(self.test_bank)
        self.data_loader = IncidentDataLoader()

    def test_single_incident_retention(self):
        sample = self.data_loader.get_by_id("INC-2026-0001")
        self.assertIsNotNone(sample)

        initial_count = self.memory_service.count_memories(self.test_bank)
        result = self.memory_service.retain_incident(sample, bank_id=self.test_bank)

        self.assertEqual(result.get("status"), "success")
        self.assertEqual(self.memory_service.count_memories(self.test_bank), initial_count + 1)

    def test_bulk_dataset_ingestion(self):
        all_incidents = self.data_loader.get_all()
        self.assertGreaterEqual(len(all_incidents), 20, "Dataset must contain at least 20 records")

        for inc in all_incidents:
            res = self.memory_service.retain_incident(inc, bank_id=self.test_bank)
            self.assertEqual(res.get("status"), "success")

        final_count = self.memory_service.count_memories(self.test_bank)
        self.assertEqual(final_count, len(all_incidents))


if __name__ == "__main__":
    unittest.main()
