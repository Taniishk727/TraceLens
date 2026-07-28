"""
TraceLens Requests Transport

Performs HTTP requests and returns a standardized response that
matches the BrowserTransport interface.
"""

import time
import requests


import os
import time
import requests


class RequestsTransport:
    def __init__(
        self,
        timeout=10,
        allow_redirects=True,
        verify_ssl=True,
        clear_cookies_per_request=True,
    ):
        self.timeout = timeout
        self.allow_redirects = allow_redirects
        self.verify_ssl = verify_ssl
        self.clear_cookies_per_request = clear_cookies_per_request

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/138.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8,"
                "application/signed-exchange;v=b3;q=0.7"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "Sec-Ch-Ua": '"Not A(Brand";v="8", "Chromium";v="138", "Google Chrome";v="138"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        })

    def clear_cookies(self):
        """Clears session cookies to prevent stale cookies across requests."""
        self.session.cookies.clear()

    def fetch(self, url):
        start = time.time()
        debug = os.getenv("DEBUG", "").lower() in ("1", "true", "yes")

        if self.clear_cookies_per_request:
            self.clear_cookies()

        if debug:
            print(f"\n[RequestsTransport DEBUG] Outgoing GET Request: {url}")
            print(f"[RequestsTransport DEBUG] Headers: {dict(self.session.headers)}")

        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.allow_redirects,
                verify=self.verify_ssl,
            )

            elapsed = round(time.time() - start, 2)
            headers = dict(response.headers)
            redirect_history = [
                {"url": r.url, "status": r.status_code} for r in response.history
            ]

            server = headers.get("Server", "").lower()
            is_cf = (
                response.status_code == 403
                and ("cloudflare" in server or "cf-mitigated" in headers or "cf-ray" in headers)
            )

            if debug:
                print(f"[RequestsTransport DEBUG] Response Status: {response.status_code}")
                print(f"[RequestsTransport DEBUG] Final URL: {response.url}")
                print(f"[RequestsTransport DEBUG] Redirect History: {redirect_history}")
                print(f"[RequestsTransport DEBUG] Response Headers: {headers}")
                print(f"[RequestsTransport DEBUG] Server: {headers.get('Server')}")
                print(f"[RequestsTransport DEBUG] CF-Ray: {headers.get('CF-RAY')}")
                print(f"[RequestsTransport DEBUG] Cf-Mitigated: {headers.get('Cf-Mitigated')}")
                print(f"[RequestsTransport DEBUG] Cloudflare Challenge Detected: {is_cf}")

            try:
                json_data = response.json()
            except Exception:
                json_data = None

            return {
                "success": True,
                "status": response.status_code,
                "final_url": response.url,
                "headers": headers,
                "history": redirect_history,
                "html": response.text,
                "text": response.text,
                "json": json_data,
                "length": len(response.text),
                "elapsed": elapsed,
                "is_cloudflare_challenge": is_cf,
            }

        except requests.RequestException as e:
            if debug:
                print(f"[RequestsTransport DEBUG] Request Error: {e}")

            return {
                "success": False,
                "error": str(e),
                "status": None,
                "final_url": url,
                "headers": {},
                "history": [],
                "html": "",
                "text": "",
                "length": 0,
                "elapsed": round(time.time() - start, 2),
                "json": None,
                "is_cloudflare_challenge": False,
            }