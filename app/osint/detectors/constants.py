"""
============================================================
TraceLens Detector Constants
============================================================

Shared constants used across all OSINT detectors.

Purpose
-------
- Prevent duplicated literals
- Avoid typos
- Keep every detector consistent
- Provide a single source of truth

Author:
TraceLens
"""

# ==========================================================
# HTTP CONFIGURATION
# ==========================================================

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 "
        "(Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/137.0 Safari/537.36 "
        "TraceLens/3.0"
    )
}

DEFAULT_TIMEOUT = 5

DEFAULT_THREADS = 8


# ==========================================================
# DETECTION STATUS
# ==========================================================

STATUS_FOUND = "Found"

STATUS_NOT_FOUND = "Not Found"

STATUS_UNKNOWN = "Unknown"

STATUS_TIMEOUT = "Timeout"

STATUS_ERROR = "Error"

STATUS_UNSUPPORTED = "Unsupported Detector"


# ==========================================================
# DETECTOR TYPES
# ==========================================================

DETECTOR_STATUS = "status"

DETECTOR_HTML = "html"

DETECTOR_REDIRECT = "redirect"

DETECTOR_API = "api"


# ==========================================================
# DETECTOR DISPLAY NAMES
# ==========================================================

DISPLAY_STATUS = "Status Code"

DISPLAY_HTML = "HTML"

DISPLAY_REDIRECT = "Redirect"

DISPLAY_API = "API"


# ==========================================================
# CONFIDENCE SCORES
# ==========================================================

CONFIDENCE_HIGH = 100

CONFIDENCE_MEDIUM = 95

CONFIDENCE_LOW = 50

CONFIDENCE_UNKNOWN = 40

CONFIDENCE_NONE = 0


# ==========================================================
# SORT PRIORITY
# ==========================================================

STATUS_PRIORITY = {

    STATUS_FOUND: 0,

    STATUS_UNKNOWN: 1,

    STATUS_TIMEOUT: 2,

    STATUS_ERROR: 3,

    STATUS_NOT_FOUND: 4,

    STATUS_UNSUPPORTED: 5

}