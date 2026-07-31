"""
============================================================
TraceLens HTML Detector Unit Tests
============================================================

Tests for HTML detector marker matching and HackerRank profile detection.

Run:
    pytest tests/test_html.py -v
"""

from unittest.mock import Mock
from app.osint.modules.username.detectors.html import detect
from app.osint.modules.username.data.username_sites import SITES


def test_hackerrank_valid_profile():
    site = next(s for s in SITES if s["name"] == "HackerRank")
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 200,
        "final_url": "https://www.hackerrank.com/profile/aleksandar",
        "html": "<html><head><title>Aleksandar - aleksandar | HackerRank</title></head><body>Education Certifications Badges</body></html>",
        "title": "Aleksandar - aleksandar | HackerRank",
        "error": None,
    }

    result = detect(site, "aleksandar", transport)
    assert result["status"] == "Found"
    assert result["status_code"] == 200


def test_hackerrank_invalid_profile():
    site = next(s for s in SITES if s["name"] == "HackerRank")
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 200,
        "final_url": "https://www.hackerrank.com/traceLensDefinitelyInvalid123456",
        "html": "<html><head><title>Programming Problems and Competitions :: HackerRank</title></head><body>Something went wrong! Some error occured while loading page for you.</body></html>",
        "title": "Programming Problems and Competitions :: HackerRank",
        "error": None,
    }

    result = detect(site, "traceLensDefinitelyInvalid123456", transport)
    assert result["status"] == "Not Found"
    assert result["status_code"] == 200
