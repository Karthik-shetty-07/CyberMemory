
import os
import tempfile
import unittest

from backend import db
from backend.app import create_app


class FeedbackAPITest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        db.DB_PATH = os.path.join(cls.temp_dir.name, "test.db")

        app = create_app()
        cls.client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def setUp(self):
        db._run("DELETE FROM analyst_feedback")
        db._run("DELETE FROM incidents")

        incident = {
            "incident_id": "INC-113",
            "title": "DNS tunnelling test",
            "severity": "high",
            "description": "Suspicious DNS traffic",
            "alert_type": "data_exfiltration"
        }

        db.save_incident("seeded", incident, "ok")

    def test_positive_feedback(self):
        response = self.client.post(
            "/api/memory/feedback",
            headers={"X-Tenant-ID": "seeded"},
            json={
                "incident_id": "INC-113",
                "rating": "positive",
                "comment": "Very helpful"
            }
        )

        self.assertEqual(response.status_code, 201)

        counts = db.feedback_counts("seeded")
        self.assertEqual(counts["positive"], 1)

    def test_negative_feedback(self):
        response = self.client.post(
            "/api/memory/feedback",
            headers={"X-Tenant-ID": "seeded"},
            json={
                "incident_id": "INC-113",
                "rating": "negative",
                "comment": "Not useful"
            }
        )

        self.assertEqual(response.status_code, 201)

        counts = db.feedback_counts("seeded")
        self.assertEqual(counts["negative"], 1)

    def test_invalid_rating(self):
        response = self.client.post(
            "/api/memory/feedback",
            headers={"X-Tenant-ID": "seeded"},
            json={
                "incident_id": "INC-113",
                "rating": "neutral"
            }
        )

        self.assertEqual(response.status_code, 400)

    def test_invalid_incident_id(self):
        response = self.client.post(
            "/api/memory/feedback",
            headers={"X-Tenant-ID": "seeded"},
            json={
                "incident_id": "INVALID",
                "rating": "positive"
            }
        )

        self.assertEqual(response.status_code, 400)

    def test_missing_incident(self):
        response = self.client.post(
            "/api/memory/feedback",
            headers={"X-Tenant-ID": "seeded"},
            json={
                "incident_id": "INC-999",
                "rating": "positive"
            }
        )

        self.assertEqual(response.status_code, 404)

    def test_tenant_isolation(self):
        response = self.client.post(
            "/api/memory/feedback",
            headers={"X-Tenant-ID": "another-tenant"},
            json={
                "incident_id": "INC-113",
                "rating": "positive"
            }
        )

        self.assertEqual(response.status_code, 404)

    def test_invalid_tenant(self):
        response = self.client.post(
            "/api/memory/feedback",
            headers={"X-Tenant-ID": "../invalid"},
            json={
                "incident_id": "INC-113",
                "rating": "positive"
            }
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
