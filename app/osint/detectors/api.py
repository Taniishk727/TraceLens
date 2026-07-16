"""
============================================================
TraceLens API Detector
============================================================

Determines profile existence using JSON APIs.

Used For
--------
- GitHub API
- Mastodon
- Future GraphQL services
- REST-based platforms

Author:
TraceLens
"""

import requests

from app.osint.detectors.constants import (
    HEADERS,
    DEFAULT_TIMEOUT,
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    STATUS_TIMEOUT,
    DISPLAY_API,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_NONE,
)

from app.osint.detectors.common import (
    start_timer,
    stop_timer,
    build_result,
    build_error,
)


def detect(site, username, session=None):

    url = site["url"].format(username)

    timeout = site.get("timeout", DEFAULT_TIMEOUT)

    expected = site.get("expected", 200)

    request_session = session or requests.Session()

    timer = start_timer()

    try:

        response = request_session.get(
            url,
            headers=HEADERS,
            timeout=timeout
        )

        elapsed = stop_timer(timer)

        if response.status_code == expected:

            status = STATUS_FOUND
            confidence = CONFIDENCE_HIGH

        elif response.status_code == 404:

            status = STATUS_NOT_FOUND
            confidence = CONFIDENCE_HIGH

        else:

            status = STATUS_UNKNOWN
            confidence = CONFIDENCE_LOW

        return build_result(
            site=site,
            url=url,
            status=status,
            status_code=response.status_code,
            confidence=confidence,
            response_time=elapsed,
            detector=DISPLAY_API,
            extra={
                "content_type": response.headers.get("Content-Type")
            }
        )

    except requests.Timeout:

        elapsed = stop_timer(timer)

        return build_result(
            site=site,
            url=url,
            status=STATUS_TIMEOUT,
            status_code=None,
            confidence=CONFIDENCE_NONE,
            response_time=elapsed,
            detector=DISPLAY_API,
            error="Request Timed Out"
        )

    except requests.RequestException as exc:

        elapsed = stop_timer(timer)

        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_API,
            error=exc
        )

    finally:

        if session is None:
            request_session.close()