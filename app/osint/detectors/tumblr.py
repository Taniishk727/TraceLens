"""
============================================================
TraceLens Tumblr Detector
============================================================

Determines profile existence on Tumblr after Playwright
anti-bot browser challenge verification.

Author:
TraceLens
"""

from bs4 import BeautifulSoup

from app.osint.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    DISPLAY_TUMBLR,
    CONFIDENCE_HIGH,
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
    Detects if a Tumblr user profile exists.

    Parameters
    ----------
    site : dict
        Site entry from username_sites.py

    username : str
        Target Tumblr username

    transport : BrowserTransport / TransportProfilerWrapper

    Returns
    -------
    dict
    """

    url = site["url"].format(username)

    print("[Tumblr]")
    print(f"Initial URL: {url}")

    timer = start_timer()

    response = transport.fetch(url)

    elapsed = stop_timer(timer)

    if not response.get("success"):
        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_TUMBLR,
            error=response.get("error", "Unknown transport error"),
        )

    status_code = response.get("status")
    final_url = response.get("final_url", url)
    title = response.get("title", "")
    body = response.get("body", "")
    html = response.get("html", "")
    initial_title = response.get("initial_title", title)
    challenge_detected = response.get("challenge_detected", False)
    challenge_waited_seconds = response.get("challenge_waited_seconds", 0)

    if not body and html:
        soup = BeautifulSoup(html, "html.parser")
        body = soup.get_text(" ", strip=True)
        if not title and soup.title:
            title = soup.title.get_text(" ", strip=True)

    print(f"[Tumblr]\nInitial title: {initial_title}")
    if challenge_detected:
        print(f"[Tumblr]\nChallenge completed after {challenge_waited_seconds} seconds")
    print(f"[Tumblr]\nFinal title: {title}")
    print(f"[Tumblr]\nFinal URL: {final_url}")
    print(f"[Tumblr]\nBody length: {len(body)}")
    print(f"[Tumblr]\nHTML length: {len(html)}")

    # ---------------------------------------------------------
    # Final detection rules
    # ---------------------------------------------------------

    # Priority 1:
    # If body contains "There's nothing here." OR "Whatever you were looking for doesn't currently exist"
    not_found_body_match = (
        "There's nothing here." in body
        or "Whatever you were looking for doesn't currently exist" in body
    )

    # Priority 2:
    # If title == "Not found."
    not_found_title_match = (title.strip() == "Not found.")

    # Priority 3:
    # If HTML contains property="og:type" AND profile
    og_type_match = (
        ('property="og:type"' in html or "property='og:type'" in html or "og:type" in html.lower())
        and ("profile" in html.lower())
    )

    # Priority 4:
    # If HTML contains property="og:title"
    og_title_match = (
        'property="og:title"' in html
        or "property='og:title'" in html
        or "og:title" in html.lower()
    )

    # Priority 5:
    # If HTML contains property="og:url"
    og_url_match = (
        'property="og:url"' in html
        or "property='og:url'" in html
        or "og:url" in html.lower()
    )

    print(f"[Tumblr]\nWhether NOT_FOUND markers matched: {not_found_body_match or not_found_title_match}")
    print(f"[Tumblr]\nWhether FOUND markers matched: {og_type_match or og_title_match or og_url_match}")

    if not_found_body_match:
        print("[Tumblr]\nMarker matched: Not Found Body")
        print("[Tumblr]\nResult: NOT_FOUND")
        return build_result(
            site=site,
            url=url,
            status=STATUS_NOT_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_TUMBLR,
        )

    if not_found_title_match:
        print("[Tumblr]\nMarker matched: Not Found Title")
        print("[Tumblr]\nResult: NOT_FOUND")
        return build_result(
            site=site,
            url=url,
            status=STATUS_NOT_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_TUMBLR,
        )

    if og_type_match:
        print("[Tumblr]\nFound marker:\nog:type=profile")
        print("[Tumblr]\nResult: FOUND")
        return build_result(
            site=site,
            url=url,
            status=STATUS_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_TUMBLR,
        )

    if og_title_match:
        print("[Tumblr]\nFound marker:\nog:title")
        print("[Tumblr]\nResult: FOUND")
        return build_result(
            site=site,
            url=url,
            status=STATUS_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_TUMBLR,
        )

    if og_url_match:
        print("[Tumblr]\nFound marker:\nog:url")
        print("[Tumblr]\nResult: FOUND")
        return build_result(
            site=site,
            url=url,
            status=STATUS_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_TUMBLR,
        )

    print("[Tumblr]\nResult: UNKNOWN")
    return build_result(
        site=site,
        url=url,
        status=STATUS_UNKNOWN,
        status_code=status_code,
        confidence=CONFIDENCE_UNKNOWN,
        response_time=elapsed,
        detector=DISPLAY_TUMBLR,
        error="Could not determine profile existence from Tumblr page",
    )
