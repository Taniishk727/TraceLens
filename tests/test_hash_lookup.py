"""
============================================================
TraceLens Hash Lookup Unit Test Suite (Feature 2)
============================================================

Deterministic unit and API integration tests for public hash lookup
and plaintext recovery. All HTTP calls are mocked.

Author:
    TraceLens
"""

import unittest
from unittest.mock import MagicMock, patch
from app import create_app
from app.osint.modules.hash.lookup.models import (
    LookupResult,
    LookupSourceCapability,
    LookupStatus,
)
from app.osint.modules.hash.lookup.sources.hashtoolkit import HashToolkitSource
from app.osint.modules.hash.lookup.sources.crackstation import CrackStationSource
from app.osint.modules.hash.lookup.registry import LookupRegistry, execute_lookup
from app.osint.modules.hash.engine import investigate


class TestHashLookup(unittest.TestCase):

    def setUp(self):
        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    # 1. Known MD5 Hash with Known Plaintext
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_known_md5_hash_found(self, mock_fetch):
        # 5f4dcc3b5aa765d61d8327deb882cf99 -> "password"
        mock_fetch.return_value = {
            "success": True,
            "status": 200,
            "json": {"result": "password", "type": "MD5"},
            "html": "",
        }

        source = HashToolkitSource()
        res = source.lookup("5f4dcc3b5aa765d61d8327deb882cf99", possible_algorithms=["MD5"])

        self.assertEqual(res.status, LookupStatus.FOUND)
        self.assertEqual(res.plaintext, "password")
        self.assertEqual(res.source, "HashToolkit")
        self.assertEqual(res.algorithm, "MD5")

    # 2. Known SHA-1 Hash with Known Plaintext
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_known_sha1_hash_found(self, mock_fetch):
        # 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 -> "password"
        mock_fetch.return_value = {
            "success": True,
            "status": 200,
            "json": {"result": "password", "type": "SHA-1"},
            "html": "",
        }

        source = HashToolkitSource()
        res = source.lookup("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", possible_algorithms=["SHA-1"])

        self.assertEqual(res.status, LookupStatus.FOUND)
        self.assertEqual(res.plaintext, "password")
        self.assertEqual(res.algorithm, "SHA-1")

    # 3. Hash Not Present in Lookup Source (NOT_FOUND)
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_hash_not_found(self, mock_fetch):
        mock_fetch.return_value = {
            "success": True,
            "status": 200,
            "json": {},
            "html": "<div>No result</div>",
        }

        source = HashToolkitSource()
        res = source.lookup("e10adc3949ba59abbe56e057f20f883e", possible_algorithms=["MD5"])

        self.assertEqual(res.status, LookupStatus.NOT_FOUND)
        self.assertIsNone(res.plaintext)

    # 4. Unsupported Algorithm (UNSUPPORTED)
    def test_unsupported_algorithm(self):
        source = HashToolkitSource()
        # bcrypt algorithm is not supported by hashtoolkit
        res = source.lookup("$2b$12$e86..", possible_algorithms=["bcrypt"])

        self.assertEqual(res.status, LookupStatus.UNSUPPORTED)
        self.assertIsNone(res.plaintext)

    # 5. Source Unavailable / Network Error (SOURCE_UNAVAILABLE)
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_source_unavailable_on_network_error(self, mock_fetch):
        mock_fetch.return_value = {
            "success": False,
            "error": "Connection timed out",
            "status": None,
        }

        source = HashToolkitSource()
        res = source.lookup("5f4dcc3b5aa765d61d8327deb882cf99", possible_algorithms=["MD5"])

        self.assertEqual(res.status, LookupStatus.SOURCE_UNAVAILABLE)
        self.assertIsNone(res.plaintext)

    # 6. Rate Limited Response (RATE_LIMITED)
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_rate_limited_response(self, mock_fetch):
        mock_fetch.return_value = {
            "success": True,
            "status": 429,
            "json": None,
            "html": "Rate limit exceeded",
        }

        source = HashToolkitSource()
        res = source.lookup("5f4dcc3b5aa765d61d8327deb882cf99", possible_algorithms=["MD5"])

        self.assertEqual(res.status, LookupStatus.RATE_LIMITED)

    # 7. Malformed Source Response / Internal Error
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_malformed_source_response(self, mock_fetch):
        mock_fetch.side_effect = Exception("Unexpected transport failure")

        registry = LookupRegistry()
        res = registry.execute_lookup("5f4dcc3b5aa765d61d8327deb882cf99", possible_algorithms=["MD5"])

        self.assertEqual(res.status, LookupStatus.ERROR)

    # 8. Multiple Candidate Algorithms Ambiguity Handling
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_multiple_candidate_algorithms(self, mock_fetch):
        mock_fetch.return_value = {
            "success": True,
            "status": 200,
            "json": {"result": "test1234", "type": "MD5"},
            "html": "",
        }

        res = execute_lookup("5f4dcc3b5aa765d61d8327deb882cf99", possible_algorithms=["MD4", "MD5", "NTLM", "LM"])

        self.assertEqual(res.status, LookupStatus.FOUND)
        self.assertEqual(res.plaintext, "test1234")
        self.assertEqual(res.algorithm, "MD5")

    # 9. Full Engine Payload Integration with Identification and Lookup
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_full_engine_payload_structure(self, mock_fetch):
        mock_fetch.return_value = {
            "success": True,
            "status": 200,
            "json": {"result": "hello", "type": "MD5"},
        }

        res = investigate("5f4dcc3b5aa765d61d8327deb882cf99")

        self.assertTrue(res["success"])
        self.assertIn("identification", res)
        self.assertIn("lookup", res)
        self.assertEqual(res["lookup"]["status"], "found")
        self.assertEqual(res["lookup"]["plaintext"], "hello")

    # 10. API Route POST /api/hash/investigate Response Format
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_api_hash_investigate_route(self, mock_fetch):
        mock_fetch.return_value = {
            "success": True,
            "status": 200,
            "json": {"result": "secret", "type": "SHA-1"},
        }

        response = self.client.post(
            "/api/hash/investigate",
            json={"hash": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"},
        )
        self.assertEqual(response.status_code, 200)

        data = response.get_json()
        self.assertTrue(data["success"])
        self.assertIn("lookup", data)
        self.assertIn("identification", data)
        self.assertEqual(data["lookup"]["status"], "found")
        self.assertEqual(data["lookup"]["plaintext"], "secret")

    # 11. HTML Rendering for FOUND State
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_html_rendering_found_state(self, mock_fetch):
        mock_fetch.return_value = {
            "success": True,
            "status": 200,
            "json": {"result": "plaintext_password", "type": "MD5"},
        }

        response = self.client.post(
            "/hash-search",
            data={"hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
        )
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)

        self.assertIn("PLAINTEXT RECOVERY", html)
        self.assertIn("MATCH FOUND", html)
        self.assertIn("plaintext_password", html)

    # 12. HTML Rendering for NOT_FOUND State
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_html_rendering_not_found_state(self, mock_fetch):
        mock_fetch.return_value = {
            "success": True,
            "status": 200,
            "json": {},
            "html": "",
        }

        response = self.client.post(
            "/hash-search",
            data={"hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
        )
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)

        self.assertIn("PLAINTEXT RECOVERY", html)
        self.assertIn("NO MATCH FOUND", html)

    # 13. HTML Rendering for SOURCE_UNAVAILABLE State
    @patch("app.osint.core.transport.requests_transport.RequestsTransport.fetch")
    def test_html_rendering_source_unavailable_state(self, mock_fetch):
        mock_fetch.return_value = {
            "success": False,
            "error": "Timeout",
            "status": None,
        }

        response = self.client.post(
            "/hash-search",
            data={"hash": "5f4dcc3b5aa765d61d8327deb882cf99"},
        )
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)

        self.assertIn("PLAINTEXT RECOVERY", html)
        self.assertIn("LOOKUP UNAVAILABLE", html)


if __name__ == "__main__":
    unittest.main()
