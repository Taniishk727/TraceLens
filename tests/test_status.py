"""
============================================================
TraceLens Status Detector Tests
============================================================

Tests the HTTP Status Code detector.

Run:
    pytest tests/test_status.py -v

Author:
TraceLens
"""

from unittest.mock import Mock

from app.osint.detectors.status import detect

from app.osint.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    STATUS_TIMEOUT,
    STATUS_ERROR,
    DISPLAY_STATUS,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_NONE,
)


# ==========================================================
# TEST DATA
# ==========================================================

SITE = {
    "name": "GitHub",
    "category": "Developer",
    "url": "https://github.com/{}",
    "expected": 200,
    "timeout": 5
}


# ==========================================================
# FOUND
# ==========================================================

def test_found():
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 200,
        "final_url": "https://github.com/torvalds",
        "error": None
    }

    result = detect(SITE, "torvalds", transport)

    assert result["status"] == STATUS_FOUND
    assert result["status_code"] == 200
    assert result["confidence"] == CONFIDENCE_HIGH
    assert result["detector"] == DISPLAY_STATUS
    assert result["site"] == "GitHub"
    assert result["url"] == "https://github.com/torvalds"


# ==========================================================
# NOT FOUND
# ==========================================================

def test_not_found():
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 404,
        "final_url": "https://github.com/this_user_does_not_exist",
        "error": None
    }

    result = detect(SITE, "this_user_does_not_exist", transport)

    assert result["status"] == STATUS_NOT_FOUND
    assert result["status_code"] == 404
    assert result["confidence"] == CONFIDENCE_HIGH


# ==========================================================
# UNKNOWN STATUS
# ==========================================================

def test_unknown_status():
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 500,
        "final_url": "https://github.com/torvalds",
        "error": None
    }

    result = detect(SITE, "torvalds", transport)

    assert result["status"] == STATUS_UNKNOWN
    assert result["status_code"] == 500
    assert result["confidence"] == CONFIDENCE_LOW


# ==========================================================
# REQUEST TIMEOUT
# ==========================================================

def test_timeout():
    transport = Mock()
    transport.fetch.return_value = {
        "success": False,
        "status": None,
        "error": "Timeout",
    }

    result = detect(SITE, "torvalds", transport)

    assert result["status"] == STATUS_ERROR
    assert result["confidence"] == CONFIDENCE_NONE
    assert result["status_code"] is None


# ==========================================================
# REQUEST ERROR
# ==========================================================

def test_request_exception():
    transport = Mock()
    transport.fetch.return_value = {
        "success": False,
        "status": None,
        "error": "Network Error",
    }

    result = detect(SITE, "torvalds", transport)

    assert result["status"] == STATUS_ERROR
    assert result["confidence"] == CONFIDENCE_NONE
    assert result["status_code"] is None
    assert "Network Error" in result["error"]


# ==========================================================
# URL FORMAT
# ==========================================================

def test_url_formatting():
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 200,
        "final_url": "https://github.com/john_doe",
        "error": None
    }

    username = "john_doe"
    result = detect(SITE, username, transport)

    assert result["url"] == f"https://github.com/{username}"


# ==========================================================
# RESPONSE TIME
# ==========================================================

def test_response_time_exists():
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 200,
        "final_url": "https://github.com/torvalds",
        "error": None
    }

    result = detect(SITE, "torvalds", transport)

    assert isinstance(result["response_time"], float)
    assert result["response_time"] >= 0