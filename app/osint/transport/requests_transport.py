"""
TraceLens Requests Transport

Performs HTTP requests and returns a standardized response that
matches the BrowserTransport interface.
"""

import time
import requests


class RequestsTransport:
    def __init__(
        self,
        timeout=10,
        allow_redirects=True,
        verify_ssl=True,
    ):
        self.timeout = timeout
        self.allow_redirects = allow_redirects
        self.verify_ssl = verify_ssl

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/138.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive",
        })

    def fetch(self, url):
        start = time.time()

        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=self.allow_redirects,
                verify=self.verify_ssl,
            )

            elapsed = round(time.time() - start, 2)

            return {
                "success": True,
                "status": response.status_code,
                "final_url": response.url,
                "headers": dict(response.headers),
                "html": response.text,
                "length": len(response.text),
                "elapsed": elapsed,
            }

        except requests.RequestException as e:
            try:
                json_data = response.json()
            except ValueError:
                json_data = None
            
            return {
                "success": False,
                "error": str(e),
                "elapsed": round(time.time() - start, 2),
                "json": json_data
            }