"""
Test Case 9: API failures and graceful degradation.
Verifies resilience against Hindsight downtime and LLM API errors.
"""

import unittest
from unittest.mock import MagicMock
from cybermemory.memory.hindsight_service import HindsightMemoryService
from cybermemory.agent.investigator import IncidentInvestigator


class TestApiFailuresAndDegradation(unittest.TestCase):

    def test_hindsight_api_failure_informs_user_without_crashing(self):
        # Create a mock memory service that raises an exception on recall
        faulty_memory_service = HindsightMemoryService(force_mock=True)
        faulty_memory_service.recall_similar_incidents = MagicMock(
            side_effect=ConnectionError("Hindsight cloud cluster unreachable (HTTP 503)")
        )

        investigator = IncidentInvestigator(
            memory_service=faulty_memory_service,
            force_mock_llm=True
        )

        alert = {
            "incident_id": "ALERT-FAIL-01",
            "alert_type": "Suspicious outbound connections",
            "severity": "High",
            "affected_host": "WS-FIN-01.corp.local",
            "user_account": "CORP\\bob",
            "description": "Beaconing traffic to unauthorized external IP."
        }

        report = investigator.investigate(alert)

        # 1. System must not crash
        self.assertIsNotNone(report)

        # 2. Must inform user that investigation is running without historical context (never pretend)
        self.assertIn("Cold Start (Empty Memory)", report.memory_status)
        self.assertEqual(len(report.historical_correlation), 0)

    def test_llm_api_failure_falls_back_to_deterministic_rules(self):
        # Create investigator with a mock LLM failure
        investigator = IncidentInvestigator(
            force_mock_llm=False,
            groq_api_key="gsk_fake_invalid_test_key"
        )
        # Mock _call_groq_llm to raise RateLimitError
        investigator._call_groq_llm = MagicMock(
            side_effect=RuntimeError("Groq API rate limit exceeded (HTTP 429)")
        )

        alert = {
            "incident_id": "ALERT-FAIL-02",
            "alert_type": "Web server compromise",
            "severity": "Critical",
            "affected_host": "SRV-WEB-01.corp.local",
            "user_account": "tomcat",
            "description": "Log4Shell JNDI injection in HTTP header."
        }

        report = investigator.investigate(alert)

        # System falls back to deterministic synthesis and succeeds
        self.assertIsNotNone(report)
        self.assertEqual(report.incident_id, "ALERT-FAIL-02")
        self.assertGreater(len(report.investigation_plan), 0)


if __name__ == "__main__":
    unittest.main()

