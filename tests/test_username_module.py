"""
============================================================
TraceLens Username Module & Transport Unit Tests
============================================================

Tests for RequestsTransport headers, cookie isolation, and
Cloudflare 403 BrowserTransport fallback in run_detector.

Run:
    pytest tests/test_username_module.py -v
"""

from unittest.mock import Mock, patch
from app.osint.transport.requests_transport import RequestsTransport
from app.osint.modules.username import run_detector


def test_requests_transport_modern_headers():
    transport = RequestsTransport()
    headers = transport.session.headers

    assert "Mozilla/5.0" in headers["User-Agent"]
    assert "Chrome/138" in headers["User-Agent"]
    assert headers["Accept-Language"] == "en-US,en;q=0.9"
    assert headers["Connection"] == "keep-alive"
    assert headers["Upgrade-Insecure-Requests"] == "1"
    assert headers["Cache-Control"] == "max-age=0"
    assert "Sec-Ch-Ua" in headers
    assert "Sec-Fetch-Dest" in headers


def test_requests_transport_cookie_clearing():
    transport = RequestsTransport(clear_cookies_per_request=True)
    transport.session.cookies.set("stale_cookie", "12345", domain="leetcode.com")
    assert len(transport.session.cookies) == 1

    transport.clear_cookies()
    assert len(transport.session.cookies) == 0


@patch("app.osint.modules.username.REQUESTS_TRANSPORT")
@patch("app.osint.modules.username.BROWSER_TRANSPORT")
def test_cloudflare_403_fallback_triggered(mock_browser, mock_requests):
    mock_requests.fetch.return_value = {
        "success": True,
        "status": 403,
        "final_url": "https://leetcode.com/u/leetcode",
        "headers": {"Server": "cloudflare", "Cf-Mitigated": "challenge"},
        "html": "<html>Cloudflare challenge</html>",
        "is_cloudflare_challenge": True,
    }

    mock_browser.fetch.return_value = {
        "success": True,
        "status": 200,
        "final_url": "https://leetcode.com/u/leetcode",
        "headers": {"Server": "cloudflare"},
        "html": "<html>Profile loaded</html>",
        "is_cloudflare_challenge": False,
    }

    site = {
        "name": "LeetCode",
        "category": "Competitive Programming",
        "url": "https://leetcode.com/u/{}",
        "detector": "status",
        "transport": "requests",
        "expected": 200,
    }

    result = run_detector(site, "leetcode")

    # Assert fallback to BROWSER_TRANSPORT happened
    mock_requests.fetch.assert_called_once_with("https://leetcode.com/u/leetcode")
    mock_browser.fetch.assert_called_once_with("https://leetcode.com/u/leetcode")
    assert result["status"] == "Found"
    assert result["status_code"] == 200
