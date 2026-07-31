"""
============================================================
TraceLens Crates.io Detector Unit Tests
============================================================

Tests Crates.io API detection for valid users, invalid users,
and transport errors.

Run:
    pytest tests/test_crates.py -v
"""

from unittest.mock import Mock

from app.osint.modules.username.detectors.api import detect
from app.osint.modules.username.data.username_sites import SITES
from app.osint.modules.username.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_ERROR,
    DISPLAY_API,
    CONFIDENCE_HIGH,
    CONFIDENCE_NONE,
)


def get_crates_site():
    return next(s for s in SITES if s["name"] == "Crates.io")


# ==========================================================
# VALID USER -> FOUND
# ==========================================================

def test_crates_valid_user():
    site = get_crates_site()
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 200,
        "final_url": "https://crates.io/api/v1/users/dtolnay",
        "text": '{"user":{"id":3618,"login":"dtolnay","name":"David Tolnay"}}',
        "json": {"user": {"id": 3618, "login": "dtolnay", "name": "David Tolnay"}},
        "headers": {"content-type": "application/json"},
        "error": None,
    }

    result = detect(site, "dtolnay", transport)

    assert result["status"] == STATUS_FOUND
    assert result["status_code"] == 200
    assert result["confidence"] == CONFIDENCE_HIGH
    assert result["detector"] == DISPLAY_API
    assert result["site"] == "Crates.io"
    assert result["url"] == "https://crates.io/users/dtolnay"
    transport.fetch.assert_called_once_with("https://crates.io/api/v1/users/dtolnay")


# ==========================================================
# NON-EXISTENT USER -> NOT_FOUND
# ==========================================================

def test_crates_invalid_user():
    site = get_crates_site()
    transport = Mock()
    transport.fetch.return_value = {
        "success": True,
        "status": 404,
        "final_url": "https://crates.io/api/v1/users/this_user_does_not_exist_123456789987",
        "text": '{"errors":[{"detail":"Not Found"}]}',
        "json": {"errors": [{"detail": "Not Found"}]},
        "headers": {"content-type": "application/json"},
        "error": None,
    }

    result = detect(site, "this_user_does_not_exist_123456789987", transport)

    assert result["status"] == STATUS_NOT_FOUND
    assert result["status_code"] == 404
    assert result["confidence"] == CONFIDENCE_HIGH
    assert result["detector"] == DISPLAY_API
    assert result["site"] == "Crates.io"
    assert result["url"] == "https://crates.io/users/this_user_does_not_exist_123456789987"
    transport.fetch.assert_called_once_with("https://crates.io/api/v1/users/this_user_does_not_exist_123456789987")


# ==========================================================
# TRANSPORT / NETWORK ERROR
# ==========================================================

def test_crates_transport_error():
    site = get_crates_site()
    transport = Mock()
    transport.fetch.return_value = {
        "success": False,
        "status": None,
        "headers": {},
        "error": "Connection refused",
    }

    result = detect(site, "dtolnay", transport)

    assert result["status"] == STATUS_ERROR
    assert result["confidence"] == CONFIDENCE_NONE
    assert result["status_code"] is None
    assert "Connection refused" in result["error"]
