"""
============================================================
TraceLens HTML Detector (v4)
============================================================

Determines profile existence using HTML content.

Detection order

    1. HTTP Status
    2. Not-found markers
    3. Found markers
    4. Login wall
    5. Unknown
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
    # Facebook-specific detection
    # (Must run before generic marker logic)
    # ----------------------------------------------------

    if site.get("name") == "Facebook":

        title_raw = response.get("title") or title

        not_found_marker = "this content isn't available at the moment"
        has_followers     = "followers" in raw_text
        has_following     = "following" in raw_text
        title_is_generic  = title_raw.strip().lower() == "facebook"
        is_not_found      = not_found_marker in raw_text

        print("------------------------------------")
        print("Facebook Detector")
        print(f"URL:    {url}")
        print(f"Status: {status_code}")
        print(f"Final URL: {response.get('final_url', url)}")
        print(f"Title:  {title_raw}")
        print(f"Followers: {has_followers}")
        print(f"Following: {has_following}")
        print(f"Not Found Marker: {is_not_found}")

        if is_not_found:
            print("Decision: NOT_FOUND")
            print("------------------------------------")
            return build_result(
                site=site,
                url=url,
                status=STATUS_NOT_FOUND,
                status_code=status_code,
                confidence=CONFIDENCE_HIGH,
                response_time=elapsed,
                detector=DISPLAY_HTML,
            )

        if not title_is_generic and has_followers and has_following:
            print("Decision: FOUND")
            print("------------------------------------")
            return build_result(
                site=site,
                url=url,
                status=STATUS_FOUND,
                status_code=status_code,
                confidence=CONFIDENCE_HIGH,
                response_time=elapsed,
                detector=DISPLAY_HTML,
            )

        print("Decision: UNKNOWN")
        print("------------------------------------")
        return build_result(
            site=site,
            url=url,
            status=STATUS_UNKNOWN,
            status_code=status_code,
            confidence=CONFIDENCE_UNKNOWN,
            response_time=elapsed,
            detector=DISPLAY_HTML,
            error="Could not determine profile existence from Facebook page",
        )

    # ----------------------------------------------------
    # Pinterest-specific detection
    # (Must run before generic marker logic)
    # ----------------------------------------------------

    if site.get("name") == "Pinterest":

        final_url = response.get("final_url", url)
        title_raw = response.get("title") or title

        has_show_error    = "show_error=true" in final_url.lower()
        title_has_profile = "profile | pinterest" in title_raw.lower() or "pinterest" in title_raw.lower()
        has_followers     = "followers" in raw_text
        has_following     = "following" in raw_text

        if has_show_error:
            decision = "NOT_FOUND"
        elif title_has_profile and has_followers and has_following:
            decision = "FOUND"
        else:
            decision = "UNKNOWN"

        print("------------------------------------------------\n")
        print("Pinterest Detector\n")
        print(f"HTTP Status:\n{status_code}\n")
        print(f"Final URL:\n{final_url}\n")
        print(f"Title:\n{title_raw if title_raw else '(empty)'}\n")
        print(f"Followers:\n{has_followers}\n")
        print(f"Following:\n{has_following}\n")
        print(f"show_error=true:\n{has_show_error}\n")
        print(f"Decision:\n{decision}\n")
        print("------------------------------------------------")

        if decision == "NOT_FOUND":
            return build_result(
                site=site,
                url=url,
                status=STATUS_NOT_FOUND,
                status_code=status_code,
                confidence=CONFIDENCE_HIGH,
                response_time=elapsed,
                detector=DISPLAY_HTML,
            )

        if decision == "FOUND":
            return build_result(
                site=site,
                url=url,
                status=STATUS_FOUND,
                status_code=status_code,
                confidence=CONFIDENCE_HIGH,
                response_time=elapsed,
                detector=DISPLAY_HTML,
            )

        return build_result(
            site=site,
            url=url,
            status=STATUS_UNKNOWN,
            status_code=status_code,
            confidence=CONFIDENCE_UNKNOWN,
            response_time=elapsed,
            detector=DISPLAY_HTML,
            error="Could not determine profile existence from Pinterest page",
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
    # Found markers (Moved BEFORE login detection)
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
    # Login wall
    # ----------------------------------------------------

    if login_markers and any(marker in searchable_text for marker in login_markers):

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