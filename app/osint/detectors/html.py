"""
============================================================
TraceLens HTML Detector
============================================================

Determines whether a profile exists by inspecting the HTML
returned by a website.

Used For
--------
- Instagram
- Pinterest
- Reddit
- Kaggle
- Canva
- Figma
- Any website requiring HTML inspection

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
    DISPLAY_HTML,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_UNKNOWN,
    CONFIDENCE_NONE,
)

from app.osint.detectors.common import (
    start_timer,
    stop_timer,
    build_result,
    build_error,
)


# ==========================================================
# HTML DETECTOR
# ==========================================================

def detect(site, username, session=None):
    """
    Detect username using HTML page content.
    """

    url = site["url"].format(username)

    timeout = site.get(
        "timeout",
        DEFAULT_TIMEOUT
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

        html = response.text.lower()

        # --------------------------------------------------
        # Explicit "Not Found" markers
        # --------------------------------------------------

        for phrase in site.get("not_found", []):

            if phrase.lower() in html:

                return build_result(
                    site=site,
                    url=url,
                    status=STATUS_NOT_FOUND,
                    status_code=response.status_code,
                    confidence=CONFIDENCE_MEDIUM,
                    response_time=elapsed,
                    detector=DISPLAY_HTML
                )

        # --------------------------------------------------
        # Explicit "Found" markers
        # --------------------------------------------------

        for phrase in site.get("found", []):

            if phrase.lower() in html:

                return build_result(
                    site=site,
                    url=url,
                    status=STATUS_FOUND,
                    status_code=response.status_code,
                    confidence=CONFIDENCE_MEDIUM,
                    response_time=elapsed,
                    detector=DISPLAY_HTML
                )

        # --------------------------------------------------
        # No marker matched
        # --------------------------------------------------

        return build_result(
            site=site,
            url=url,
            status=STATUS_UNKNOWN,
            status_code=response.status_code,
            confidence=CONFIDENCE_UNKNOWN,
            response_time=elapsed,
            detector=DISPLAY_HTML,
            error="No HTML markers matched"
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
            detector=DISPLAY_HTML,
            error="Request Timed Out"
        )

    except requests.RequestException as exc:

        elapsed = stop_timer(timer)

        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_HTML,
            error=exc
        )

    finally:

        if session is None:

            request_session.close()