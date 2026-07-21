"""
TraceLens Browser Transport

Persistent Playwright browser transport.

- Launches Chromium only once.
- Creates a fresh page for every request.
- Returns a standardized response compatible with RequestsTransport.
"""

import atexit
import threading
import time

from playwright.sync_api import sync_playwright


class BrowserTransport:

    def __init__(
        self,
        headless=True,
        timeout=15000,
        wait_time=3000,
        viewport=(1366, 768),
    ):

        self.headless = headless
        self.timeout = timeout
        self.wait_time = wait_time
        self.viewport = viewport

        self._lock = threading.Lock()

        self._playwright = None
        self._browser = None
        self._started = False

        self.start()

        atexit.register(self.close)

    # ------------------------------------------------------------------ #
    # Browser lifecycle
    # ------------------------------------------------------------------ #

    def start(self):

        if self._started:
            return

        self._playwright = sync_playwright().start()

        self._browser = self._playwright.chromium.launch(
            headless=self.headless
        )

        self._started = True

    def close(self):

        if not self._started:
            return

        try:
            self._browser.close()
        except Exception:
            pass

        try:
            self._playwright.stop()
        except Exception:
            pass

        self._started = False

    # ------------------------------------------------------------------ #
    # Fetch
    # ------------------------------------------------------------------ #

    def fetch(self, url):

        with self._lock:

            start = time.time()

            context = self._browser.new_context(
                viewport={
                    "width": self.viewport[0],
                    "height": self.viewport[1],
                },
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/138.0.0.0 Safari/537.36"
                ),
                locale="en-US",
            )

            page = context.new_page()

            graphql = []

            def capture_response(response):

                try:

                    if "graphql" in response.url.lower():

                        graphql.append(
                            {
                                "url": response.url,
                                "status": response.status,
                            }
                        )

                except Exception:
                    pass

            page.on("response", capture_response)

            try:

                response = page.goto(
                    url,
                    wait_until="domcontentloaded",
                    timeout=self.timeout,
                )

                try:
                    page.wait_for_load_state(
                        "networkidle",
                        timeout=5000,
                    )
                except Exception:
                    pass

                page.wait_for_timeout(self.wait_time)

                html = page.content()

                result = {
                    "success": True,
                    "status": response.status if response else None,
                    "final_url": page.url,
                    "title": page.title(),
                    "headers": dict(response.headers)
                    if response
                    else {},
                    "html": html,
                    "length": len(html),
                    "elapsed": round(
                        time.time() - start,
                        2,
                    ),
                    "graphql": graphql,
                }

            except Exception as e:

                result = {
                    "success": False,
                    "error": str(e),
                    "json": None,
                    "elapsed": round(
                        time.time() - start,
                        2,
                    ),
                }

            finally:

                page.close()
                context.close()

            return result