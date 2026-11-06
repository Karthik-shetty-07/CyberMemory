"""
Test Case 3: Retrieval of similar incidents.
Verifies recall accuracy, similarity ranking, and multi-indicator matching.
"""

import unittest
from cybermemory.data_loader import IncidentDataLoader
from cybermemory.memory.hindsight_service import HindsightMemoryService


class TestMemoryRetrieval(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_bank = "test_retrieval_bank"
        cls.memory_service = HindsightMemoryService(force_mock=True)
        cls.memory_service.clear_bank(cls.test_bank)
        loader = IncidentDataLoader()
        for inc in loader.get_all():
            cls.memory_service.retain_incident(inc, bank_id=cls.test_bank)

    def test_recall_powershell_amsi_incident(self):
        query = "PowerShell Base64 winword cdn-update-auth.com AMSI"
        matches = self.memory_service.recall_similar_incidents(query, bank_id=self.test_bank, top_k=3)

        self.assertGreater(len(matches), 0)
        top_ids = [m.incident_id for m in matches]
        # Should retrieve either INC-2026-0001 or INC-2026-0021
        self.assertTrue("INC-2026-0001" in top_ids or "INC-2026-0021" in top_ids)
        self.assertGreater(matches[0].similarity_score, 0.0)
        self.assertIsNotNone(matches[0].historical_root_cause)
        self.assertIsNotNone(matches[0].remediation_outcome)

    def test_recall_ransomware_incident(self):
        query = "Ransomware locked extension vssadmin shadow copies bcdedit"
        matches = self.memory_service.recall_similar_incidents(query, bank_id=self.test_bank, top_k=3)

        self.assertGreater(len(matches), 0)
        top_ids = [m.incident_id for m in matches]
        self.assertTrue("INC-2026-0003" in top_ids or "INC-2026-0013" in top_ids)
        combined_text = (
            matches[0].historical_root_cause + " " +
            matches[0].remediation_outcome + " " +
            matches[0].lessons_learned + " " +
            " ".join(matches[0].investigation_steps)
        ).lower()
        self.assertTrue("vssadmin" in combined_text or "shadow" in combined_text)

    def test_recall_with_unmatched_query_returns_empty(self):
        query = "quantum supercomputing teleportation particle entanglement"
        matches = self.memory_service.recall_similar_incidents(query, bank_id=self.test_bank, top_k=3)
        self.assertEqual(len(matches), 0)


if __name__ == "__main__":
    unittest.main()
