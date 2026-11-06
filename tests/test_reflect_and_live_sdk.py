"""Tests for /api/reflect and the live Hindsight SDK field mapping (using a fake client)."""

import unittest
from types import SimpleNamespace

from cybermemory.api.app import create_app
from cybermemory.memory.hindsight_service import HindsightMemoryService


class ReflectEndpointTest(unittest.TestCase):

    def setUp(self):
        self.client = create_app().test_client()

    def test_rejects_missing_query(self):
        self.assertEqual(self.client.post("/api/reflect", json={}).status_code, 400)
        self.assertEqual(self.client.post("/api/reflect", json={"query": "  "}).status_code, 400)

    def test_returns_synthesis(self):
        res = self.client.post("/api/reflect", json={"query": "PowerShell lessons learned"})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()["data"]
        self.assertIn("synthesis", data)
        self.assertIn("mode", data)


class FakeHindsight:
    """Mimics the SDK shapes: recall -> .results[].text, reflect -> .text."""

    def __init__(self):
        self.retained = []

    def retain(self, **kw):
        self.retained.append(kw)
        return SimpleNamespace(success=True)

    def recall(self, bank_id, query):
        return SimpleNamespace(results=[
            SimpleNamespace(id="m1", text="Incident ID: INC-2026-0801\nRoot Cause: Phishing macro\nLessons Learned: Block macros"),
            SimpleNamespace(id="m2", text="Unrelated memory without structure"),
        ])

    def reflect(self, bank_id, query):
        return SimpleNamespace(text="Phishing macros recur; enforce macro blocking.")

    def list_memories(self, bank_id, limit, offset):
        return SimpleNamespace(total=7)


class LiveSdkMappingTest(unittest.TestCase):

    def make_live(self):
        svc = HindsightMemoryService(force_mock=True)
        svc._client = FakeHindsight()
        svc._is_live_connected = True
        return svc

    def test_not_live_without_server(self):
        svc = HindsightMemoryService(base_url="http://127.0.0.1:1")
        self.assertFalse(svc.is_live)

    def test_recall_uses_results_and_text(self):
        matches = self.make_live().recall_similar_incidents("macro phishing")
        self.assertEqual(len(matches), 2)
        self.assertEqual(matches[0].incident_id, "INC-2026-0801")
        self.assertEqual(matches[0].historical_root_cause, "Phishing macro")
        self.assertGreater(matches[0].similarity_score, matches[1].similarity_score)

    def test_reflect_uses_text(self):
        out = self.make_live().reflect_on_incidents("macros?")
        self.assertEqual(out["mode"], "live_hindsight")
        self.assertIn("macro blocking", out["synthesis"])

    def test_retain_keeps_metadata(self):
        svc = self.make_live()
        svc.retain_incident({"incident_id": "INC-2026-0900", "alert_type": "x", "root_cause": "rc"})
        sent = svc._client.retained[0]
        self.assertEqual(sent["document_id"], "INC-2026-0900")
        self.assertEqual(sent["metadata"]["root_cause"], "rc")
        self.assertTrue(all(isinstance(v, str) for v in sent["metadata"].values()))

    def test_count_uses_live(self):
        self.assertEqual(self.make_live().count_memories(), 7)


if __name__ == "__main__":
    unittest.main()
