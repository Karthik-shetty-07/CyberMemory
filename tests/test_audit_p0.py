import json, os, tempfile, unittest
from cybermemory.api.app import create_app
from cybermemory.memory.hindsight_service import HindsightMemoryService


def _client(**cfg):
    base = {"FORCE_MOCK_MEMORY": True, "FORCE_MOCK_LLM": True}
    base.update(cfg)
    app = create_app(base)
    return app.test_client()


class ApiErrorCodes(unittest.TestCase):
    def test_unknown_route_404(self):
        self.assertEqual(_client().get("/api/nope").status_code, 404)

    def test_wrong_method_405(self):
        self.assertEqual(_client().get("/api/investigate").status_code, 405)

    def test_invalid_alert_400(self):
        r = _client().post("/api/investigate", json={"alert_type": "x", "description": "d"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["status"], "error")


class FeedbackNoFabrication(unittest.TestCase):
    def test_missing_fields_not_invented(self):
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "mem.json")
        c = _client(MEMORY_PERSISTENCE_FILE=path)
        r = c.post("/api/feedback", json={"incident_id": "INC-1", "rating": "Helpful", "actual_outcome": "False Positive"})
        self.assertEqual(r.status_code, 200)
        content = list(json.load(open(path)).values())[0][0]["content"]
        for fake in ("Confirmed by analyst", "Executed remediation", "Analyst confirmed resolution procedure"):
            self.assertNotIn(fake, content)
        self.assertIn("Not provided", content)


class RecallRegexScope(unittest.TestCase):
    def test_module_imports_re(self):
        import cybermemory.memory.hindsight_service as m
        self.assertTrue(hasattr(m, "re"))


if __name__ == "__main__":
    unittest.main()
