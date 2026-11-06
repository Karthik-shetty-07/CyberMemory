"""
Test Case 8: Incorrect historical information and conflict resolution.
Verifies that historical memories are treated as supporting evidence rather than unquestionable truth,
and that superseded advice is properly qualified.
"""

import unittest
from cybermemory.memory.hindsight_service import HindsightMemoryService
from cybermemory.agent.investigator import IncidentInvestigator


class TestIncorrectHistoricalInformation(unittest.TestCase):

    def setUp(self):
        self.test_bank = "test_conflict_bank"
        self.memory_service = HindsightMemoryService(force_mock=True)
        self.memory_service.clear_bank(self.test_bank)

        # Ingest an outdated record recommending manual script execution that was later superseded
        outdated_incident = {
            "incident_id": "INC-OUTDATED-99",
            "alert_type": "Suspicious PowerShell execution",
            "description": "Legacy PowerShell investigation from 2023.",
            "root_cause": "Unsigned PowerShell script run by admin.",
            "remediation": "Do not isolate host; manually edit registry key Run to delete payload.",
            "final_outcome": "Superseded Historical Information - Deprecated Procedure",
            "analyst_feedback": {
                "rating": "Not Helpful",
                "comments": "Manual registry cleanup was superseded by automated EDR isolation policy. This manual step is deprecated."
            },
            "lessons_learned": "Never use manual registry edits for active malware; use EDR network isolation immediately."
        }
        self.memory_service.retain_incident(outdated_incident, bank_id=self.test_bank)

        self.investigator = IncidentInvestigator(
            memory_service=self.memory_service,
            force_mock_llm=True
        )

    def test_historical_memory_treated_as_evidence_not_absolute_truth(self):
        alert = {
            "incident_id": "ALERT-POW-NEW",
            "alert_type": "Suspicious PowerShell execution",
            "severity": "High",
            "affected_host": "WS-NEW-01.corp.local",
            "user_account": "CORP\\dev_user",
            "description": "PowerShell executing encoded payload.",
            "raw_logs": "powershell.exe -enc ..."
        }

        report = self.investigator.investigate(alert, bank_id=self.test_bank)

        # 1. Historical correlation must be clearly labeled as evidence, not unquestionable truth
        self.assertEqual(len(report.historical_correlation), 1)
        self.assertEqual(report.historical_correlation[0].incident_id, "INC-OUTDATED-99")

        # 2. Containment recommendations must NOT blindly execute manual registry edits; must mandate human analyst signoff
        for rec in report.recommended_containment:
            self.assertIn("REQUIRES HUMAN AUTHORIZATION", rec)

        # 3. Limitations section must state that findings require analyst validation
        self.assertIn("Analyst must confirm", report.confidence_and_limitations)


if __name__ == "__main__":
    unittest.main()
