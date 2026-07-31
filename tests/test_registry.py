"""
============================================================
TraceLens Detector Registry Tests
============================================================
"""

from app.osint.detectors.registry import (
    get_detector,
    is_registered,
    list_detectors,
)


def test_redirect_detector_registered():
    assert is_registered("redirect")
    detector = get_detector("redirect")
    assert callable(detector)


def test_list_detectors_includes_redirect():
    detectors = list_detectors()
    assert "redirect" in detectors
    assert "status" in detectors
    assert "html" in detectors
    assert "api" in detectors
