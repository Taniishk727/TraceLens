"""
============================================================
TraceLens Redirect Detector Tests
============================================================

Tests the Redirect detector (Location header and status code detection).

Run:
    pytest tests/test_redirect.py -v
"""

from unittest.mock import Mock

from app.osint.modules.username.detectors.redirect import detect
from app.osint.modules.username.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    STATUS_ERROR,
    DISPLAY_REDIRECT,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_NONE,
)

SITE_KOFI = {
    "name": "Ko-fi",
    "category": "Portfolio",
    "url": "https://ko-fi.com/{}",
    "detector": "redirect",
    "transport": "requests",
    "timeout": 5,
    "found_status": [200],
    "not_found_status": [302],
    "not_found_redirect": "/"
}


# ==========================================================
# 200 WITH NO REDIRECT -> FOUND
# ==========================================================

def test_found_200_no_redirect():
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 200,
        "final_url": "https://ko-fi.com/jarrod",
        "headers": {},
        "error": None
    }

    result = detect(SITE_KOFI, "jarrod", transport)

    assert result["status"] == STATUS_FOUND
    assert result["status_code"] == 200
    assert result["confidence"] == CONFIDENCE_HIGH
    assert result["detector"] == DISPLAY_REDIRECT
    assert result["site"] == "Ko-fi"
    assert result["url"] == "https://ko-fi.com/jarrod"
    transport.fetch.assert_called_once_with("https://ko-fi.com/jarrod", allow_redirects=False)


# ==========================================================
# 302 WITH LOCATION "/" -> NOT_FOUND
# ==========================================================

def test_not_found_302_location_slash():
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 302,
        "final_url": "https://ko-fi.com/invalid_username_12345",
        "headers": {"Location": "/"},
        "error": None
    }

    result = detect(SITE_KOFI, "invalid_username_12345", transport)

    assert result["status"] == STATUS_NOT_FOUND
    assert result["status_code"] == 302
    assert result["confidence"] == CONFIDENCE_HIGH
    assert result["detector"] == DISPLAY_REDIRECT
    transport.fetch.assert_called_once_with("https://ko-fi.com/invalid_username_12345", allow_redirects=False)


# ==========================================================
# 302 WITH ANOTHER LOCATION -> UNKNOWN
# ==========================================================

def test_unknown_302_another_location():
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 302,
        "final_url": "https://ko-fi.com/jarrod",
        "headers": {"Location": "/another-path"},
        "error": None
    }

    result = detect(SITE_KOFI, "jarrod", transport)

    assert result["status"] == STATUS_UNKNOWN
    assert result["status_code"] == 302
    assert result["confidence"] == CONFIDENCE_LOW
    assert result["detector"] == DISPLAY_REDIRECT


# ==========================================================
# 500 -> UNKNOWN
# ==========================================================

def test_unknown_500_status():
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 500,
        "final_url": "https://ko-fi.com/jarrod",
        "headers": {},
        "error": None
    }

    result = detect(SITE_KOFI, "jarrod", transport)

    assert result["status"] == STATUS_UNKNOWN
    assert result["status_code"] == 500
    assert result["confidence"] == CONFIDENCE_LOW
    assert result["detector"] == DISPLAY_REDIRECT


# ==========================================================
# TRANSPORT ERROR
# ==========================================================

def test_transport_error():
    transport = Mock()
    transport.fetch.return_value = {
        "success": False,
        "status": None,
        "headers": {},
        "error": "Connection failed"
    }

    result = detect(SITE_KOFI, "jarrod", transport)

    assert result["status"] == STATUS_ERROR
    assert result["confidence"] == CONFIDENCE_NONE
    assert result["status_code"] is None
    assert "Connection failed" in result["error"]
