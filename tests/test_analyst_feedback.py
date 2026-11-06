"""
Test Case 5: Analyst feedback retention.
Verifies that analyst feedback and actual investigation outcomes are stored and retained in Hindsight.
"""

import unittest
from cybermemory.memory.hindsight_service import HindsightMemoryService


class TestAnalystFeedbackRetention(unittest.TestCase):

    def setUp(self):
        self.test_bank = "test_feedback_bank"
        self.memory_service = HindsightMemoryService(force_mock=True)
        self.memory_service.clear_bank(self.test_bank)

    def test_record_feedback_and_reflect(self):
        # 1. Store an incident with analyst feedback
        feedback_record = {
            "incident_id": "INC-FEEDBACK-01",
            "alert_type": "Suspicious PowerShell execution",
            "description": "Base64 encoded script block detected.",
            "root_cause": "Malicious macro in quarterly invoice.",
            "remediation": "EDR host isolation and macro GPO update.",
            "final_outcome": "True Positive - Contained",
            "analyst_feedback": {
                "rating": "Helpful",
                "comments": "The AMSI scan buffer check recommended by CyberMemory AI led directly to finding the memory-resident payload."
            },
            "lessons_learned": "Always dump AmsiScanBuffer address on parent Word processes."
        }

        retain_res = self.memory_service.retain_incident(feedback_record, bank_id=self.test_bank)
        self.assertEqual(retain_res.get("status"), "success")

        # 2. Recall the memory and verify feedback content
        recalled = self.memory_service.recall_similar_incidents(
            query="AMSI scan buffer Word macro",
            bank_id=self.test_bank,
            top_k=1
        )
        self.assertEqual(len(recalled), 1)
        self.assertEqual(recalled[0].incident_id, "INC-FEEDBACK-01")

        # 3. Trigger Hindsight Reflection across stored memories
        reflection = self.memory_service.reflect_on_incidents(
            query="What are the best practices for AMSI bypass detection?",
            bank_id=self.test_bank
        )
        self.assertIn("synthesis", reflection)
        self.assertIn("INC-FEEDBACK-01", reflection["synthesis"])


if __name__ == "__main__":
    unittest.main()

