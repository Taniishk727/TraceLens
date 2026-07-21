"""
============================================================
TraceLens Status Code Detector
============================================================

Determines whether a profile exists using HTTP status codes.
"""

from app.osint.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    DISPLAY_STATUS,
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

    url = site["url"].format(username)

    expected = site.get("expected", 200)

    timer = start_timer()

    response = transport.fetch(url)

    elapsed = stop_timer(timer)

    if not response["success"]:

        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_STATUS,
            error=response.get("error", "Unknown transport error"),
        )

    status_code = response["status"]

    if status_code == expected:

        status = STATUS_FOUND
        confidence = CONFIDENCE_HIGH

    elif status_code == 404:

        status = STATUS_NOT_FOUND
        confidence = CONFIDENCE_HIGH

    else:

        status = STATUS_UNKNOWN
        confidence = CONFIDENCE_LOW

    return build_result(
        site=site,
        url=url,
        status=status,
        status_code=status_code,
        confidence=confidence,
        response_time=elapsed,
        detector=DISPLAY_STATUS,
    )