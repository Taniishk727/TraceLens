"""
============================================================
TraceLens API Detector Unit Tests
============================================================

Tests for API detector logic and GeeksforGeeks API configuration.

Run:
    pytest tests/test_api.py -v
"""

from unittest.mock import Mock
from app.osint.detectors.api import detect
from app.osint.data.username_sites import SITES


def test_geeksforgeeks_api_valid_user():
    site = next(s for s in SITES if s["name"] == "GeeksforGeeks")
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 200,
        "final_url": "https://authapi.geeksforgeeks.org/api-get/user-profile-info/?handle=sandeepjain",
        "text": '{"message":"data retrieved successfully","data":{"name":"Sandeep"}}',
        "json": {"message": "data retrieved successfully", "data": {"name": "Sandeep"}},
        "headers": {"Content-Type": "application/json"},
        "error": None,
    }

    result = detect(site, "sandeepjain", transport)
    assert result["status"] == "Found"
    assert result["status_code"] == 200
    assert result["confidence"] == 100


def test_geeksforgeeks_api_invalid_user():
    site = next(s for s in SITES if s["name"] == "GeeksforGeeks")
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 400,
        "final_url": "https://authapi.geeksforgeeks.org/api-get/user-profile-info/?handle=traceLensDefinitelyInvalid987654",
        "text": '{"message":"User not found!"}',
        "json": {"message": "User not found!"},
        "headers": {"Content-Type": "application/json"},
        "error": None,
    }

    result = detect(site, "traceLensDefinitelyInvalid987654", transport)
    assert result["status"] == "Not Found"
    assert result["status_code"] == 400
    assert result["confidence"] == 100
