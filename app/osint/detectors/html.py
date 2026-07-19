"""
============================================================
TraceLens HTML Detector (v2)
============================================================
"""

import requests
from bs4 import BeautifulSoup

from app.osint.detectors.constants import (
    HEADERS,
    DEFAULT_TIMEOUT,
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    STATUS_TIMEOUT,
    DISPLAY_HTML,
    CONFIDENCE_HIGH,
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


def detect(site, username, session=None):
    """
    Detect username using HTML page content.

    Detection order:
        1. HTTP status
        2. Not-found markers
        3. Login wall
        4. Found markers
        5. Unknown
    """

   
    url = site["url"].format(username)
    timeout = site.get("timeout", DEFAULT_TIMEOUT)

    request_session = session or requests.Session()
    timer = start_timer()

    try:
        headers = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/138.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml",
    "Accept-Language": "en-US,en;q=0.9",
}
        response = request_session.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True
        )
        elapsed = stop_timer(timer)

        soup = BeautifulSoup(response.text, "html.parser")

        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        body = soup.get_text(" ", strip=True)

        raw_text = response.text.lower()
        parsed_text = f"{title} {body}".lower()
        searchable_text = raw_text + "\n" + parsed_text

       


        found_markers = [m.lower() for m in site.get("found", [])]
        not_found_markers = [m.lower() for m in site.get("not_found", [])]

        login_markers = [
            m.lower() for m in site.get(
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

        not_found_status = site.get("not_found_status", [404, 410])

        if response.status_code in not_found_status:
            
            return build_result(
                site=site,
                url=url,
                status=STATUS_NOT_FOUND,
                status_code=response.status_code,
                confidence=CONFIDENCE_MEDIUM,
                response_time=elapsed,
                detector=DISPLAY_HTML,
            )

        for marker in not_found_markers:
            if marker in searchable_text:
               
                return build_result(
                    site=site,
                    url=url,
                    status=STATUS_NOT_FOUND,
                    status_code=response.status_code,
                    confidence=CONFIDENCE_MEDIUM,
                    response_time=elapsed,
                    detector=DISPLAY_HTML,
                )

        if any(marker in searchable_text for marker in login_markers):
            
            return build_result(
                site=site,
                url=url,
                status=STATUS_UNKNOWN,
                status_code=response.status_code,
                confidence=CONFIDENCE_UNKNOWN,
                response_time=elapsed,
                detector=DISPLAY_HTML,
                error="Authentication/Login required",
            )

        
        matches = 0
        # for marker in found_markers:
        #     found = marker in searchable_text
        #     print(f"  {marker!r} -> {found}")
        #     if found:
        #         matches += 1
       

        if matches:
            confidence = CONFIDENCE_HIGH if matches >= 2 else CONFIDENCE_MEDIUM
            
            return build_result(
                site=site,
                url=url,
                status=STATUS_FOUND,
                status_code=response.status_code,
                confidence=confidence,
                response_time=elapsed,
                detector=DISPLAY_HTML,
            )

        
        return build_result(
            site=site,
            url=url,
            status=STATUS_UNKNOWN,
            status_code=response.status_code,
            confidence=CONFIDENCE_UNKNOWN,
            response_time=elapsed,
            detector=DISPLAY_HTML,
            error="No HTML markers matched",
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
            error="Request Timed Out",
        )

    except requests.RequestException as exc:
        elapsed = stop_timer(timer)
        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_HTML,
            error=exc,
        )

    finally:
        if session is None:
            request_session.close()
