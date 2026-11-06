
import unittest
from unittest.mock import patch

from backend.app import create_app


class MemoryExplorerAPITest(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()
        self.headers = {"X-Tenant-ID": "seeded"}

    @patch("backend.routes.memory_routes.hs.list_memory_units")
    def test_memory_listing(self, mock_list):
        mock_list.return_value = {
            "status": "ok",
            "memories": [{"id": "memory-1", "type": "world"}],
            "total": 1,
            "limit": 20,
            "offset": 0
        }

        response = self.client.get(
            "/api/memory/explorer",
            headers=self.headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["total"], 1)
        self.assertEqual(len(response.json["memories"]), 1)

    @patch("backend.routes.memory_routes.hs.list_memory_units")
    def test_type_filter(self, mock_list):
        mock_list.return_value = {
            "status": "ok",
            "memories": [{"id": "memory-1", "type": "world"}],
            "total": 1,
            "limit": 5,
            "offset": 0
        }

        response = self.client.get(
            "/api/memory/explorer?type=world&limit=5",
            headers=self.headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["memories"][0]["type"], "world")
        mock_list.assert_called_once()
        self.assertEqual(
            mock_list.call_args.kwargs["memory_type"], "world"
        )

    @patch("backend.routes.memory_routes.hs.list_memory_units")
    def test_search_filter(self, mock_list):
        mock_list.return_value = {
            "status": "ok",
            "memories": [],
            "total": 0,
            "limit": 5,
            "offset": 0
        }

        response = self.client.get(
            "/api/memory/explorer?q=PowerShell&limit=5",
            headers=self.headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            mock_list.call_args.kwargs["search_query"], "PowerShell"
        )

    @patch("backend.routes.memory_routes.hs.list_memory_units")
    def test_pagination(self, mock_list):
        mock_list.return_value = {
            "status": "ok",
            "memories": [],
            "total": 100,
            "limit": 5,
            "offset": 10
        }

        response = self.client.get(
            "/api/memory/explorer?limit=5&offset=10",
            headers=self.headers
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["limit"], 5)
        self.assertEqual(response.json["offset"], 10)

    def test_invalid_limit(self):
        response = self.client.get(
            "/api/memory/explorer?limit=101",
            headers=self.headers
        )

        self.assertEqual(response.status_code, 400)

    def test_negative_offset(self):
        response = self.client.get(
            "/api/memory/explorer?offset=-1",
            headers=self.headers
        )

        self.assertEqual(response.status_code, 400)

    def test_invalid_tenant(self):
        response = self.client.get(
            "/api/memory/explorer",
            headers={"X-Tenant-ID": "INVALID TENANT!"}
        )

        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
