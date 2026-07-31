"""
============================================================
TraceLens TryHackMe Detector
============================================================

Determines profile existence on TryHackMe using Playwright
browser transport.

Author:
TraceLens
"""

from bs4 import BeautifulSoup

from app.osint.modules.username.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    DISPLAY_TRYHACKME,
    CONFIDENCE_HIGH,
    CONFIDENCE_UNKNOWN,
)

from app.osint.modules.username.detectors.common import (
    start_timer,
    stop_timer,
    build_result,
    build_error,
)


def detect(site, username, transport):
    """
    Detects if a TryHackMe user profile exists.

    Parameters
    ----------
    site : dict
        Site entry from username_sites.py

    username : str
        Target TryHackMe username

    transport : BrowserTransport / TransportProfilerWrapper

    Returns
    -------
    dict
    """

    url = site["url"].format(username)

    print("[TryHackMe]")
    print(f"Initial URL: {url}")

    timer = start_timer()

    response = transport.fetch(url)

    elapsed = stop_timer(timer)

    if not response.get("success"):
        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_TRYHACKME,
            error=response.get("error", "Unknown transport error"),
        )

    status_code = response.get("status")
    final_url = response.get("final_url", url)
    title = response.get("title", "")
    html = response.get("html", "")
    og_image = response.get("og_image", "")

    if not og_image and html:
        soup = BeautifulSoup(html, "html.parser")
        meta = soup.find("meta", property="og:image") or soup.find("meta", attrs={"name": "og:image"})
        if meta and meta.get("content"):
            og_image = meta["content"]

    print(f"[TryHackMe]\nFinal title: {title}")
    print(f"[TryHackMe]\nFinal URL: {final_url}")
    print(f"[TryHackMe]\nog:image: {og_image}")

    # ---------------------------------------------------------
    # Detection Rules
    # ---------------------------------------------------------

    # 1. Not Found Check: URL ends with /not-found OR title contains "404 - Page not found"
    is_not_found = final_url.endswith("/not-found") or ("404 - Page not found" in title)

    # 2. Found Check: meta[property='og:image'] contains "user-avatars"
    is_found = "user-avatars" in og_image.lower()

    if is_not_found:
        print("[TryHackMe]\nResult: NOT_FOUND")
        return build_result(
            site=site,
            url=url,
            status=STATUS_NOT_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_TRYHACKME,
        )

    if is_found:
        print("[TryHackMe]\nFound marker:\nog:image contains user-avatars")
        print("[TryHackMe]\nResult: FOUND")
        return build_result(
            site=site,
            url=url,
            status=STATUS_FOUND,
            status_code=status_code,
            confidence=CONFIDENCE_HIGH,
            response_time=elapsed,
            detector=DISPLAY_TRYHACKME,
        )

    print("[TryHackMe]\nResult: UNKNOWN")
    return build_result(
        site=site,
        url=url,
        status=STATUS_UNKNOWN,
        status_code=status_code,
        confidence=CONFIDENCE_UNKNOWN,
        response_time=elapsed,
        detector=DISPLAY_TRYHACKME,
        error="Could not determine profile existence from TryHackMe page",
    )
