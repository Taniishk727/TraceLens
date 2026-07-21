"""
============================================================
TraceLens HTML Detector (v3)
============================================================

Determines profile existence using HTML content.

Networking is handled by the selected Transport.
This detector only analyzes the returned HTML.
"""

from bs4 import BeautifulSoup

from app.osint.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    DISPLAY_HTML,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
)

from app.osint.detectors.common import (
    start_timer,
    stop_timer,
    build_result,
    build_error,
)


def detect(site, username, transport):
    """
    Detection order

        1. HTTP Status
        2. Not-found markers
        3. Login wall
        4. Found markers
        5. Unknown
    """

    url = site["url"].format(username)

    timer = start_timer()

    response = transport.fetch(url)

    elapsed = stop_timer(timer)

    if not response["success"]:
        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_HTML,
            error=response.get("error", "Unknown transport error"),
        )

    status_code = response["status"]

    html = response["html"]

    soup = BeautifulSoup(html, "html.parser")

    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    body = soup.get_text(" ", strip=True)

    raw_text = html.lower()
    parsed_text = f"{title} {body}".lower()

    searchable_text = raw_text + "\n" + parsed_text

    found_markers = [
        marker.lower()
        for marker in site.get("found", [])
    ]

    not_found_markers = [
        marker.lower()
        for marker in site.get("not_found", [])
    ]

    login_markers = [
        marker.lower()
        for marker in site.get(
            "login_markers",
            [
                "log in",
                "login",
                "sign in",
                "create account",
                "authentication required",
                "continue with",
            ],
        )
    ]

    not_found_status = site.get(
        "not_found_status",
        [404, 410]
    )

    # ----------------------------------------------------
    # HTTP Status
    # ----------------------------------------------------

    if status_code in not_found_status:

        return build_result(
            site=site,
            url=url,
            status=STATUS_NOT_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_MEDIUM,
            response_time=elapsed,
            detector=DISPLAY_HTML,
        )

    # ----------------------------------------------------
    # Not-found markers
    # ----------------------------------------------------

    for marker in not_found_markers:

        if marker in searchable_text:

            return build_result(
                site=site,
                url=url,
                status=STATUS_NOT_FOUND,
                status_code=status_code,
                confidence=CONFIDENCE_MEDIUM,
                response_time=elapsed,
                detector=DISPLAY_HTML,
            )

    # ----------------------------------------------------
    # Login wall
    # ----------------------------------------------------

    if any(marker in searchable_text for marker in login_markers):

        return build_result(
            site=site,
            url=url,
            status=STATUS_UNKNOWN,
            status_code=status_code,
            confidence=CONFIDENCE_UNKNOWN,
            response_time=elapsed,
            detector=DISPLAY_HTML,
            error="Authentication/Login required",
        )

    # ----------------------------------------------------
    # Found markers
    # ----------------------------------------------------

    matches = 0

    for marker in found_markers:

        if marker in searchable_text:
            matches += 1

    if matches:

        confidence = (
            CONFIDENCE_HIGH
            if matches >= 2
            else CONFIDENCE_MEDIUM
        )

        return build_result(
            site=site,
            url=url,
            status=STATUS_FOUND,
            status_code=status_code,
            confidence=confidence,
            response_time=elapsed,
            detector=DISPLAY_HTML,
        )

    # ----------------------------------------------------
    # Unknown
    # ----------------------------------------------------

    return build_result(
        site=site,
        url=url,
        status=STATUS_UNKNOWN,
        status_code=status_code,
        confidence=CONFIDENCE_UNKNOWN,
        response_time=elapsed,
        detector=DISPLAY_HTML,
        error="No HTML markers matched",
    )