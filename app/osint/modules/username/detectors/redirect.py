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

from app.osint.modules.username.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    DISPLAY_REDIRECT,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
)

from app.osint.modules.username.detectors.common import (
    start_timer,
    stop_timer,
    build_result,
    build_error,
)


def detect(site, username, transport):
    """
    Detect username using redirect behavior.

    The transport layer performs the HTTP request.
    This detector analyzes the response status code and Location header.
    """

    url = site["url"].format(username)

    found_status = site.get("found_status", [200])
    not_found_status = site.get("not_found_status", [302])
    not_found_redirect = site.get("not_found_redirect")

    # Handle legacy site configurations using 'redirect_not_found'
    if not_found_redirect is None and "redirect_not_found" in site:
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
        final_url = response.get("final_url", "").lower()

        if status_code in site.get("not_found_status", [404, 410]):
            return build_result(
                site=site,
                url=url,
                status=STATUS_NOT_FOUND,
                status_code=status_code,
                confidence=CONFIDENCE_HIGH,
                response_time=elapsed,
                detector=DISPLAY_REDIRECT,
                extra={"final_url": response.get("final_url")}
            )

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
                extra={"final_url": response.get("final_url")}
            )

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
                    extra={"final_url": response.get("final_url")}
                )

        return build_result(
            site=site,
            url=url,
            status=STATUS_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_REDIRECT,
            extra={"final_url": response.get("final_url")}
        )

    # --------------------------------------------------
    # Location Header / Initial Response Redirect Detector
    # --------------------------------------------------

    timer = start_timer()

    response = transport.fetch(url, allow_redirects=False)

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
    headers = response.get("headers", {}) or {}

    location = None
    if isinstance(headers, dict):
        for k, v in headers.items():
            if k.lower() == "location":
                location = v
                break

    # FOUND: status code is in found_status AND no redirect occurred
    if status_code in found_status and not location:
        return build_result(
            site=site,
            url=url,
            status=STATUS_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_REDIRECT,
            extra={"location": location}
        )

    # NOT_FOUND: status code is in not_found_status AND Location header exactly matches not_found_redirect
    if status_code in not_found_status and location == not_found_redirect:
        return build_result(
            site=site,
            url=url,
            status=STATUS_NOT_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_REDIRECT,
            extra={"location": location}
        )

    # Otherwise: UNKNOWN
    return build_result(
        site=site,
        url=url,
        status=STATUS_UNKNOWN,
        status_code=status_code,
        confidence=CONFIDENCE_LOW,
        response_time=elapsed,
        detector=DISPLAY_REDIRECT,
        extra={"location": location}
    )