"""
============================================================
TraceLens Detector Common Utilities
============================================================

Shared helper functions used by every detector.

Responsibilities
----------------
- Timer utilities
- Standard result builder
- Standard error builder

Every detector should use these helpers instead of creating
its own response dictionaries.

Author:
TraceLens
"""

import time

from app.osint.detectors.constants import (
    STATUS_ERROR,
    DISPLAY_STATUS,
    CONFIDENCE_NONE
)


# ==========================================================
# TIMER UTILITIES
# ==========================================================

def start_timer():
    """
    Starts a high-resolution timer.
    """
    return time.perf_counter()


def stop_timer(start):
    """
    Returns elapsed time in milliseconds.
    """
    return round((time.perf_counter() - start) * 1000, 2)


# ==========================================================
# RESULT BUILDERS
# ==========================================================

def build_result(
    *,
    site,
    url,
    status,
    status_code,
    confidence,
    response_time,
    detector,
    error=None,
    extra=None
):
    """
    Builds a standardized detector result.

    Parameters
    ----------
    site : dict
        Site configuration from username_sites.py

    url : str
        Investigated profile URL

    status : str
        Detection status

    status_code : int | None

    confidence : int

    response_time : float

    detector : str

    error : str | None

    extra : dict | None
        Optional detector-specific fields.

    Returns
    -------
    dict
    """

    result = {

        "site": site["name"],

        "category": site.get(
            "category",
            "Unknown"
        ),

        "url": url,

        "status": status,

        "status_code": status_code,

        "confidence": confidence,

        "response_time": response_time,

        "detector": detector,

        "error": error

    }

    if extra:

        result.update(extra)

    return result


# ==========================================================
# ERROR RESULT
# ==========================================================

def build_error(
    *,
    site,
    url,
    response_time,
    error,
    detector=DISPLAY_STATUS
):
    """
    Creates a standardized detector error response.
    """

    return build_result(

        site=site,

        url=url,

        status=STATUS_ERROR,

        status_code=None,

        confidence=CONFIDENCE_NONE,

        response_time=response_time,

        detector=detector,

        error=str(error)

    )


# ==========================================================
# SUMMARY HELPERS
# ==========================================================

def count_status(profiles, status):
    """
    Counts the number of profiles matching a status.
    """

    return sum(
        profile["status"] == status
        for profile in profiles
    )


def sort_profiles(profiles, priority_map):
    """
    Sort profiles using the supplied priority map.
    """

    profiles.sort(

        key=lambda profile: (

            priority_map.get(
                profile["status"],
                99
            ),

            profile["site"]

        )

    )

    return profiles