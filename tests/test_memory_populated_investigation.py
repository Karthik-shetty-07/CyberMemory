"""
Test Case 4: Investigation after memory is populated.
Verifies that the agent incorporates past root causes and lessons learned into its recommendations.
"""

import unittest
from cybermemory.data_loader import IncidentDataLoader
from cybermemory.memory.hindsight_service import HindsightMemoryService
from cybermemory.agent.investigator import IncidentInvestigator


class TestMemoryPopulatedInvestigation(unittest.TestCase):

    def setUp(self):
        self.test_bank = "test_populated_bank"
        self.memory_service = HindsightMemoryService(force_mock=True)
        self.memory_service.clear_bank(self.test_bank)

        # Ingest INC-2026-0001 (initial PowerShell phishing dropper)
        loader = IncidentDataLoader()
        prior_inc = loader.get_by_id("INC-2026-0001")
        self.memory_service.retain_incident(prior_inc, bank_id=self.test_bank)

        self.investigator = IncidentInvestigator(
            memory_service=self.memory_service,
            force_mock_llm=True
        )

    def test_investigation_uses_retrieved_memory_in_plan(self):
        # New alert on different host WS-FIN-099 with similar indicators
        new_alert = {
            "incident_id": "ALERT-POP-99",
            "alert_type": "Suspicious PowerShell execution",
            "severity": "High",
            "affected_host": "WS-FIN-099.corp.local",
            "user_account": "CORP\\richard.hendricks",
            "description": "Base64 encoded powershell process downloading stage2 from cdn-update-auth.com with AMSI bypass.",
            "raw_logs": "powershell.exe -enc ... cdn-update-auth.com/payload/stage2.ps1"
        }

        report = self.investigator.investigate(new_alert, bank_id=self.test_bank)

        # 1. Memory status indicates active memory retrieval
        self.assertIn("Active Memory", report.memory_status)

        # 2. Historical correlation contains INC-2026-0001
        self.assertGreater(len(report.historical_correlation), 0)
        self.assertEqual(report.historical_correlation[0].incident_id, "INC-2026-0001")

        # 3. Investigation plan references INC-2026-0001
        referenced_steps = [s for s in report.investigation_plan if s.historical_reference == "INC-2026-0001"]
        self.assertGreater(len(referenced_steps), 0)

        # 4. Root cause references historical context
        found_hist_context = any("[HISTORICAL CONTEXT]" in rc for rc in report.potential_root_causes)
        self.assertTrue(found_hist_context)

        # 5. Containment is marked as advisory requiring human signoff
        for action in report.recommended_containment:
            self.assertIn("REQUIRES HUMAN AUTHORIZATION", action)


if __name__ == "__main__":
    unittest.main()
