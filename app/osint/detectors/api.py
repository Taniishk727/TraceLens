"""
============================================================
TraceLens API Detector
============================================================

Determines profile existence using JSON APIs.

Supported API Modes
-------------------
1. Default (HTTP status)
2. non_empty_list
3. json_field
"""

import json

from app.osint.detectors.constants import (
    STATUS_FOUND,
    STATUS_NOT_FOUND,
    STATUS_UNKNOWN,
    DISPLAY_API,
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
)

from app.osint.detectors.common import (
    start_timer,
    stop_timer,
    build_result,
    build_error,
)


def get_field_value(data, field_path):
    """
    Retrieves value of field_path in data.
    Supports top-level keys ('username') and dot-notation ('data.user.username').
    Returns (exists: bool, value: Any)
    """
    if not isinstance(data, dict):
        return False, None

    if field_path in data:
        return True, data[field_path]

    parts = field_path.split(".")
    curr = data
    for part in parts:
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        else:
            return False, None
    return True, curr


def parse_json_response(response):
    """
    Safely parse JSON.

    Handles Meta and generic API anti-CSRF prefixes like:
        for (;;);{"username":"zuck"}
        )]}'
        while(1);
    """
    data = response.get("json")

    if data is not None and isinstance(data, (dict, list)):
        return data

    text = response.get("text")
    if text is None:
        text = response.get("html", "")

    if not text or not isinstance(text, str):
        return None

    text = text.strip()

    # Generic anti-CSRF script prefix removal
    prefixes = ["for (;;);", "for(;;);", ")]}'", "while(1);", "<!--"]
    for prefix in prefixes:
        if text.startswith(prefix):
            text = text[len(prefix):].strip()
            break

    try:
        return json.loads(text)
    except Exception:
        return None


def detect(site, username, transport):

    url = site.get("api_url", site["url"]).format(username)

    expected = site.get("expected", 200)

    timer = start_timer()

    response = transport.fetch(url)

    elapsed = stop_timer(timer)

    if not response["success"]:
        return build_error(
            site=site,
            url=url,
            response_time=elapsed,
            detector=DISPLAY_API,
            error=response.get("error", "Unknown transport error"),
        )

    status_code = response["status"]
    headers = response.get("headers", {})
    content_type = headers.get("Content-Type") or headers.get("content-type") or "Unknown"

    raw_body = response.get("text")
    if raw_body is None:
        raw_body = response.get("html", "")
    raw_len = len(raw_body)
    first_300 = raw_body[:300]

    api_mode = site.get("api_mode")
    data = parse_json_response(response)

    not_found_status = site.get("not_found_status", [404])
    decision_reason = ""

    # Check for HTTP status codes indicating NOT_FOUND
    if status_code in not_found_status:
        status = STATUS_NOT_FOUND
        confidence = CONFIDENCE_HIGH
        decision_reason = f"HTTP status {status_code} in not_found_status"

    # ======================================================
    # API MODE : NON EMPTY LIST
    # ======================================================

    elif api_mode == "non_empty_list":

        if status_code != 200:
            status = STATUS_UNKNOWN
            confidence = CONFIDENCE_LOW
            decision_reason = f"HTTP status {status_code} != 200"

        elif isinstance(data, list):

            if len(data) > 0:
                status = STATUS_FOUND
                confidence = CONFIDENCE_HIGH
                decision_reason = f"JSON list has {len(data)} items"
            else:
                status = STATUS_NOT_FOUND
                confidence = CONFIDENCE_HIGH
                decision_reason = "JSON list is empty"

        else:
            status = STATUS_UNKNOWN
            confidence = CONFIDENCE_LOW
            decision_reason = "Response is not a JSON list"

    # ======================================================
    # API MODE : JSON FIELD
    # ======================================================

    elif api_mode == "json_field":

        if not isinstance(data, dict):

            status = STATUS_UNKNOWN
            confidence = CONFIDENCE_LOW
            decision_reason = "JSON parsing failed or response is not a JSON dict"

        else:

            field = site.get("json_field")
            field_exists, value = get_field_value(data, field)

            if not field_exists:
                status = STATUS_UNKNOWN
                confidence = CONFIDENCE_LOW
                decision_reason = f"Field '{field}' does not exist in JSON response"

            elif value is None or value == "":
                status = STATUS_NOT_FOUND
                confidence = CONFIDENCE_HIGH
                decision_reason = f"Parsed field '{field}' = {value!r} (null/empty)"

            elif isinstance(value, str) and value.strip() != "":
                status = STATUS_FOUND
                confidence = CONFIDENCE_HIGH
                decision_reason = f"Parsed field '{field}' = {value!r} (non-empty string)"

            elif value:
                status = STATUS_FOUND
                confidence = CONFIDENCE_HIGH
                decision_reason = f"Parsed field '{field}' = {value!r} (truthy value)"

            else:
                status = STATUS_NOT_FOUND
                confidence = CONFIDENCE_HIGH
                decision_reason = f"Parsed field '{field}' = {value!r} (falsy value)"

    # ======================================================
    # DEFAULT MODE
    # ======================================================

    else:

        if status_code == expected:

            status = STATUS_FOUND
            confidence = CONFIDENCE_HIGH
            decision_reason = f"HTTP status {status_code} matches expected {expected}"

        elif status_code == 404:

            status = STATUS_NOT_FOUND
            confidence = CONFIDENCE_HIGH
            decision_reason = "HTTP status is 404"

        else:

            status = STATUS_UNKNOWN
            confidence = CONFIDENCE_LOW
            decision_reason = f"HTTP status {status_code} != expected {expected}"

    print(f"\n[API Detector] Site: {site.get('name')}")
    print(f"API URL used   : {url}")
    print(f"HTTP status    : {status_code}")
    print(f"Content-Type   : {content_type}")
    print(f"Raw body length: {raw_len}")
    print(f"First 300 chars: {first_300!r}")
    print(f"Parsed JSON    : {data}")
    print(f"Decision taken : {status}")
    print(f"Reason         : {decision_reason}\n")

    return build_result(
        site=site,
        url=url,
        status=status,
        status_code=status_code,
        confidence=confidence,
        response_time=elapsed,
        detector=DISPLAY_API,
        extra={
            "content_type": content_type
        }
    )