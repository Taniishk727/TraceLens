"""
============================================================
TraceLens Detector Registry
============================================================

Central registry for all detector implementations.

Each detector is registered exactly once here.

The username investigation engine loads detectors from this
registry instead of importing them directly.

Author:
TraceLens
"""

from app.osint.detectors import (
    status,
    html,
    redirect,
    api,
)

from app.osint.detectors.constants import (
    DETECTOR_STATUS,
    DETECTOR_HTML,
    DETECTOR_REDIRECT,
    DETECTOR_API,
)


# ==========================================================
# DETECTOR REGISTRY
# ==========================================================

DETECTOR_REGISTRY = {

    DETECTOR_STATUS: status.detect,

    DETECTOR_HTML: html.detect,

    DETECTOR_REDIRECT: redirect.detect,

    DETECTOR_API: api.detect,

}


# ==========================================================
# HELPER FUNCTIONS
# ==========================================================

def get_detector(detector_name):
    """
    Returns the detector function for a detector name.

    Parameters
    ----------
    detector_name : str

    Returns
    -------
    callable | None
    """

    return DETECTOR_REGISTRY.get(detector_name)


def is_registered(detector_name):
    """
    Checks whether a detector exists.
    """

    return detector_name in DETECTOR_REGISTRY


def list_detectors():
    """
    Returns all registered detector names.
    """

    return sorted(DETECTOR_REGISTRY.keys())