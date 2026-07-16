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

import requests

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

    session = Mock()

    response = Mock()

    response.status_code = 200

    session.get.return_value = response

    result = detect(SITE, "torvalds", session)

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

    session = Mock()

    response = Mock()

    response.status_code = 404

    session.get.return_value = response

    result = detect(SITE, "this_user_does_not_exist", session)

    assert result["status"] == STATUS_NOT_FOUND

    assert result["status_code"] == 404

    assert result["confidence"] == CONFIDENCE_HIGH


# ==========================================================
# UNKNOWN STATUS
# ==========================================================

def test_unknown_status():

    session = Mock()

    response = Mock()

    response.status_code = 500

    session.get.return_value = response

    result = detect(SITE, "torvalds", session)

    assert result["status"] == STATUS_UNKNOWN

    assert result["status_code"] == 500

    assert result["confidence"] == CONFIDENCE_LOW


# ==========================================================
# REQUEST TIMEOUT
# ==========================================================

def test_timeout():

    session = Mock()

    session.get.side_effect = requests.Timeout()

    result = detect(SITE, "torvalds", session)

    assert result["status"] == STATUS_TIMEOUT

    assert result["confidence"] == CONFIDENCE_NONE

    assert result["status_code"] is None


# ==========================================================
# REQUEST ERROR
# ==========================================================

def test_request_exception():

    session = Mock()

    session.get.side_effect = requests.ConnectionError("Network Error")

    result = detect(SITE, "torvalds", session)

    assert result["status"] == STATUS_ERROR

    assert result["confidence"] == CONFIDENCE_NONE

    assert result["status_code"] is None

    assert "Network Error" in result["error"]


# ==========================================================
# URL FORMAT
# ==========================================================

def test_url_formatting():

    session = Mock()

    response = Mock()

    response.status_code = 200

    session.get.return_value = response

    username = "john_doe"

    result = detect(SITE, username, session)

    assert result["url"] == f"https://github.com/{username}"


# ==========================================================
# RESPONSE TIME
# ==========================================================

def test_response_time_exists():

    session = Mock()

    response = Mock()

    response.status_code = 200

    session.get.return_value = response

    result = detect(SITE, "torvalds", session)

    assert isinstance(result["response_time"], float)

    assert result["response_time"] >= 0