"""
============================================================
TraceLens Status Code Detector
============================================================

Determines whether a profile exists using HTTP status codes.

This detector is used for websites where profile existence can
be determined directly from the HTTP response status.

Examples
--------
- GitHub
- GitLab
- Reddit
- HackerOne
- Bugcrowd
- Docker Hub

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
    DISPLAY_STATUS,
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


# ==========================================================
# STATUS DETECTOR
# ==========================================================

def detect(site, username, session=None):
    """
    Detect username using HTTP status codes.

    Parameters
    ----------
    site : dict
        Site configuration.

    username : str
        Username being investigated.

    session : requests.Session | None
        Existing HTTP session.

    Returns
    -------
    dict
        Standard TraceLens detector result.
    """

    url = site["url"].format(username)

    timeout = site.get(
        "timeout",
        DEFAULT_TIMEOUT
    )

    expected = site.get(
        "expected",
        200
    )

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

        # ----------------------------------------------
        # Detection
        # ----------------------------------------------

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

            detector=DISPLAY_STATUS

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

            detector=DISPLAY_STATUS,

            error="Request Timed Out"

        )

    except requests.RequestException as exc:

        elapsed = stop_timer(timer)

        return build_error(

            site=site,

            url=url,

            response_time=elapsed,

            detector=DISPLAY_STATUS,

            error=exc

        )

    finally:

        if session is None:

            request_session.close()