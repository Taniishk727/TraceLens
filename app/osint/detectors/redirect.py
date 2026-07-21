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

from app.osint.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    DISPLAY_REDIRECT,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
)

from app.osint.detectors.common import (
    start_timer,
    stop_timer,
    build_result,
    build_error,
)


def detect(site, username, transport):
    """
    Detect username using redirect behavior.

    The transport layer performs the HTTP request.
    This detector only analyzes the response.
    """

    url = site["url"].format(username)

    redirect_markers = [
        marker.lower()
        for marker in site.get("redirect_not_found", [])
    ]

    timer = start_timer()

    response = transport.fetch(url)

    elapsed = stop_timer(timer)

    if not response["success"]:
        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_REDIRECT,
            error=response.get("error", "Unknown transport error"),
        )

    status_code = response["status"]
    final_url = response["final_url"].lower()

    # --------------------------------------------------
    # HTTP Status takes precedence
    # --------------------------------------------------

    if status_code in site.get("not_found_status", [404, 410]):
        return build_result(
            site=site,
            url=url,
            status=STATUS_NOT_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_REDIRECT,
            extra={
                "final_url": response["final_url"]
            }
        )

    # --------------------------------------------------
    # Login wall / Bot protection
    # --------------------------------------------------

    if status_code in site.get("unknown_status", [401, 403, 429, 999]):
        return build_result(
            site=site,
            url=url,
            status=STATUS_UNKNOWN,
            status_code=status_code,
            confidence=CONFIDENCE_LOW,
            response_time=elapsed,
            detector=DISPLAY_REDIRECT,
            error="Authentication or bot protection",
            extra={
                "final_url": response["final_url"]
            }
        )

    # --------------------------------------------------
    # Redirect markers
    # --------------------------------------------------

    for marker in redirect_markers:

        if marker in final_url:

            return build_result(
                site=site,
                url=url,
                status=STATUS_NOT_FOUND,
                status_code=status_code,
                confidence=CONFIDENCE_HIGH,
                response_time=elapsed,
                detector=DISPLAY_REDIRECT,
                extra={
                    "final_url": response["final_url"]
                }
            )

    # --------------------------------------------------
    # Found
    # --------------------------------------------------

    return build_result(
        site=site,
        url=url,
        status=STATUS_FOUND,
        status_code=status_code,
        confidence=CONFIDENCE_HIGH,
        response_time=elapsed,
        detector=DISPLAY_REDIRECT,
        extra={
            "final_url": response["final_url"]
        }
    )