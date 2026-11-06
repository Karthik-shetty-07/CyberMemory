"""
Test Case 1: New investigation with empty memory.
Verifies cold-start behavior, fallback to general playbooks,
and transparent declaration that no historical context exists.
"""

import unittest
from cybermemory.models import AlertInput
from cybermemory.memory.hindsight_service import HindsightMemoryService
from cybermemory.agent.investigator import IncidentInvestigator


class TestEmptyMemoryInvestigation(unittest.TestCase):

    def setUp(self):
        # Create an isolated memory service with an empty test bank
        self.test_bank = "test_empty_bank"
        self.memory_service = HindsightMemoryService(force_mock=True)
        self.memory_service.clear_bank(self.test_bank)
        self.investigator = IncidentInvestigator(
            memory_service=self.memory_service,
            force_mock_llm=True
        )

    def test_investigation_with_empty_memory_declares_cold_start(self):
        alert = {
            "incident_id": "ALERT-EMPTY-01",
            "alert_type": "Suspicious PowerShell execution",
            "severity": "High",
            "affected_host": "WS-TEST-001.corp.local",
            "user_account": "CORP\\alice",
            "description": "Base64 encoded powershell process spawned by winword.exe with WebClient download.",
            "raw_logs": "powershell.exe -enc SQBFAFgA... Parent: winword.exe"
        }

        report = self.investigator.investigate(alert, bank_id=self.test_bank)

        # 1. Memory status must clearly inform user of cold-start mode
        self.assertIn("Cold Start (Empty Memory)", report.memory_status)
        self.assertIn("Running without historical context", report.memory_status)

        # 2. Historical correlation must be empty (never hallucinate memories)
        self.assertEqual(len(report.historical_correlation), 0)

        # 3. Investigation plan must still be generated using baseline heuristics
        self.assertGreater(len(report.investigation_plan), 0)
        for step in report.investigation_plan:
            self.assertIsNone(step.historical_reference)

        # 4. Read-only analysis mode enforced
        self.assertEqual(report.operational_mode, "READ_ONLY_ANALYSIS")

        # 5. Potential root causes should be clearly tagged as unconfirmed hypotheses
        for rc in report.potential_root_causes:
            self.assertIn("[AI HYPOTHESIS]", rc)


if __name__ == "__main__":
    unittest.main()
