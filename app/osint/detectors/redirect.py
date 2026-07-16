"""
============================================================
TraceLens Redirect Detector
============================================================

Determines profile existence by inspecting the final redirected
URL after an HTTP request.

Used For
--------
- Twitter/X
- Websites redirecting missing profiles
- Login-gated services

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
    DISPLAY_REDIRECT,
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

    redirect_markers = site.get("redirect_not_found", [])

    request_session = session or requests.Session()

    timer = start_timer()

    try:

        response = request_session.get(
            url,
            headers=HEADERS,
            timeout=timeout,
            allow_redirects=True
        )

        elapsed = stop_timer(timer)

        final_url = response.url.lower()

        for marker in redirect_markers:

            if marker.lower() in final_url:

                return build_result(
                    site=site,
                    url=url,
                    status=STATUS_NOT_FOUND,
                    status_code=response.status_code,
                    confidence=CONFIDENCE_HIGH,
                    response_time=elapsed,
                    detector=DISPLAY_REDIRECT,
                    extra={
                        "final_url": response.url
                    }
                )

        return build_result(
            site=site,
            url=url,
            status=STATUS_FOUND,
            status_code=response.status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_REDIRECT,
            extra={
                "final_url": response.url
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
            detector=DISPLAY_REDIRECT,
            error="Request Timed Out"
        )

    except requests.RequestException as exc:

        elapsed = stop_timer(timer)

        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_REDIRECT,
            error=exc
        )

    finally:

        if session is None:
            request_session.close()