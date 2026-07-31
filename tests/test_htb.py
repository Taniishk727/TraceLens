"""
============================================================
TraceLens Hack The Box Detector Tests
============================================================

Tests that Hack The Box is removed from the username searching list.

Run:
    pytest tests/test_htb.py -v
"""

from app.osint.modules.username.data.username_sites import SITES


def test_htb_removed_from_sites():
    site_names = [s["name"] for s in SITES]
    assert "Hack The Box" not in site_names
