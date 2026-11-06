"""
Test Case 7: Irrelevant memories and distractor robustness.
Verifies that noisy, unrelated historical memories do not pollute security incident investigations.
"""

import unittest
from cybermemory.memory.hindsight_service import HindsightMemoryService
from cybermemory.agent.investigator import IncidentInvestigator


class TestIrrelevantMemories(unittest.TestCase):

    def setUp(self):
        self.test_bank = "test_distractor_bank"
        self.memory_service = HindsightMemoryService(force_mock=True)
        self.memory_service.clear_bank(self.test_bank)

        # Ingest irrelevant non-security memories into the bank
        distractors = [
            {
                "incident_id": "DISTRACT-01",
                "alert_type": "Office Printer Jam",
                "description": "Paper tray 2 reported empty and roller jammed on floor 3 laser printer.",
                "root_cause": "80gsm paper dampness caused mechanical feeding failure.",
                "remediation": "Opened duplex tray and replaced paper ream.",
                "final_outcome": "Resolved",
                "analyst_feedback": {"rating": "Helpful", "comments": "Physical maintenance."},
                "lessons_learned": "Keep spare paper reams in dry storage."
            },
            {
                "incident_id": "DISTRACT-02",
                "alert_type": "Espresso Machine Maintenance",
                "description": "Descaling cycle required for cafeteria bean grinder.",
                "root_cause": "Calcium mineral deposit accumulation.",
                "remediation": "Ran citric acid descaling flush.",
                "final_outcome": "Resolved",
                "analyst_feedback": {"rating": "Helpful", "comments": "Facilities ticket."},
                "lessons_learned": "Schedule monthly descaling."
            }
        ]
        for d in distractors:
            self.memory_service.retain_incident(d, bank_id=self.test_bank)

        self.investigator = IncidentInvestigator(
            memory_service=self.memory_service,
            force_mock_llm=True
        )

    def test_distractor_memories_are_ignored_during_security_investigation(self):
        # Ransomware security alert
        ransomware_alert = {
            "incident_id": "ALERT-RANSOM-01",
            "alert_type": "Ransomware behaviour",
            "severity": "Critical",
            "affected_host": "FS-PROD-01.corp.local",
            "user_account": "CORP\\svc_admin",
            "description": "Mass file renaming to .locked, vssadmin delete shadows invoked, and bcdedit recovery disabled.",
            "raw_logs": "vssadmin.exe delete shadows /all /quiet"
        }

        report = self.investigator.investigate(ransomware_alert, bank_id=self.test_bank)

        # 1. Distractors should not be retrieved as relevant matches
        recalled_ids = [m.incident_id for m in report.historical_correlation]
        self.assertNotIn("DISTRACT-01", recalled_ids)
        self.assertNotIn("DISTRACT-02", recalled_ids)

        # 2. Investigation plan must focus on ransomware containment, not printers or coffee
        plan_text = " ".join([s.action for s in report.investigation_plan]).lower()
        self.assertNotIn("paper", plan_text)
        self.assertNotIn("descaling", plan_text)


if __name__ == "__main__":
    unittest.main()
