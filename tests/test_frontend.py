"""
CyberMemory AI - Frontend & API route tests (stdlib unittest, no pytest needed).
Runs against the bundled in-process backend with an isolated local memory bank.
"""

import json
import os
import shutil
import tempfile
import unittest

_TMP = tempfile.mkdtemp(prefix="cm_frontend_")
os.environ.setdefault("LOCAL_BANK_DIR", os.path.join(_TMP, "banks"))
os.environ.setdefault("CM_DB_PATH", os.path.join(_TMP, "cm.db"))

from app import app  # noqa: E402


class FrontendRoutesTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(_TMP, ignore_errors=True)

    def post_json(self, url, payload):
        return self.client.post(url, data=json.dumps(payload), content_type="application/json")

    def test_page_routes_status_200(self):
        for route in ["/", "/dashboard", "/investigate", "/investigation/INC-2026-0801",
                      "/history", "/memory", "/analytics"]:
            with self.subTest(route=route):
                res = self.client.get(route)
                self.assertEqual(res.status_code, 200)
                self.assertIn(b"CyberMemory", res.data)

    def test_dashboard_stats_api(self):
        res = self.client.get("/api/dashboard/stats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        for key in ("total_investigated", "memory_items_stored", "severity_breakdown", "memory_growth"):
            self.assertIn(key, data)
        self.assertGreaterEqual(data["total_investigated"], 20)

    def test_incidents_api_and_filters(self):
        data = self.client.get("/api/incidents").get_json()
        self.assertGreaterEqual(data["total"], 20)

        for inc in self.client.get("/api/incidents?severity=Critical").get_json()["incidents"]:
            self.assertEqual(inc["severity"], "Critical")

        found = self.client.get("/api/incidents?query=powershell").get_json()
        self.assertGreaterEqual(found["total"], 1)
        self.assertTrue(any(
            "powershell" in i["title"].lower() or "powershell" in i["description"].lower()
            for i in found["incidents"]))

    def test_investigate_post_api(self):
        res = self.post_json("/api/investigate", {
            "title": "Automated Test Malicious Execution",
            "severity": "High",
            "alert_source": "CrowdStrike Falcon",
            "affected_host": "TEST-HOST-99",
            "user": "corp\\testuser",
            "description": "powershell.exe downloading remote payload from untrusted domain",
            "raw_logs": "EventID: 4688 powershell.exe -enc AAAA 198.51.100.44",
            "use_memory": True,
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("incident_id", data)
        self.assertTrue(data["investigation"]["investigation_steps"])
        self.assertIn("T1059.001", data["investigation"]["indicators"]["mitre_techniques"])

    def test_feedback_submission_and_memory_retention(self):
        res = self.post_json("/api/investigation/INC-2026-0801/feedback", {
            "rating": "Helpful",
            "final_outcome": "Confirmed Malicious",
            "root_cause_confirmed": "Verified phishing invoice attack",
            "comments": "Immediate isolation stopped lateral spread.",
            "retain_to_hindsight": True,
        })
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["feedback_saved"])
        self.assertTrue(data["hindsight_retained"])
        # No fabricated memory ids: the backend does not return one.
        self.assertIsNone(data["retained_memory_id"])

    def test_memory_search_api(self):
        data = self.client.get("/api/memory/search?q=powershell").get_json()
        self.assertIn("results", data)
        self.assertGreaterEqual(data["total_matches"], 1)

    def test_learning_analytics_api(self):
        res = self.client.get("/api/analytics/learning")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("total_memories", data)
        self.assertIn("triage_time_reduction_percentage", data)


if __name__ == "__main__":
    unittest.main()
