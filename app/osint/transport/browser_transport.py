"""
TraceLens Browser Transport

Thread-safe Playwright browser transport using a dedicated worker thread queue.
- Launches Chromium once on a dedicated background worker thread.
- Processes fetch requests via a thread-safe Task Queue.
- Preserves the standardized response dictionary format compatible with RequestsTransport.
"""

import atexit
import queue
from concurrent.futures import Future
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

        self._queue = queue.Queue()
        self._thread = threading.Thread(
            target=self._worker_loop,
            daemon=True,
            name="BrowserTransportWorker"
        )
        self._started_event = threading.Event()
        self._init_error = None
        self._stopped = False

        self._thread.start()
        # Wait until Playwright and Chromium are initialized in the worker thread
        self._started_event.wait()
        if self._init_error:
            raise RuntimeError(f"Failed to start BrowserTransport: {self._init_error}")

        atexit.register(self.close)

    # ------------------------------------------------------------------ #
    # Worker Thread Event Loop (Runs exclusively on self._thread)
    # ------------------------------------------------------------------ #

    def _worker_loop(self):
        playwright = None
        browser = None

        try:
            playwright = sync_playwright().start()
            browser = playwright.chromium.launch(headless=self.headless)
            self._started_event.set()
        except Exception as e:
            self._init_error = e
            self._started_event.set()
            return

        while True:
            item = self._queue.get()
            if item is None:
                self._queue.task_done()
                break

            url, future = item
            try:
                result = self._execute_fetch(browser, url)
                future.set_result(result)
            except Exception as e:
                future.set_exception(e)
            finally:
                self._queue.task_done()

        # Teardown inside worker thread
        try:
            if browser:
                browser.close()
            if playwright:
                playwright.stop()
        except Exception:
            pass

    def _execute_fetch(self, browser, url):
        start = time.time()
        context = browser.new_context(
            viewport={"width": self.viewport[0], "height": self.viewport[1]},
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
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass

            page.wait_for_timeout(self.wait_time)
            html = page.content()

            return {
                "success": True,
                "status": response.status if response else None,
                "final_url": page.url,
                "title": page.title(),
                "headers": dict(response.headers) if response else {},
                "html": html,
                "length": len(html),
                "elapsed": round(time.time() - start, 2),
                "graphql": graphql,
                "error": None,
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "status": None,
                "final_url": url,
                "headers": {},
                "html": "",
                "length": 0,
                "json": None,
                "elapsed": round(time.time() - start, 2),
            }
        finally:
            page.close()
            context.close()

    # ------------------------------------------------------------------ #
    # Fetch Facade (Callable from any thread)
    # ------------------------------------------------------------------ #

    def fetch(self, url):
        if self._stopped:
            return {
                "success": False,
                "error": "BrowserTransport is stopped.",
                "status": None,
                "final_url": url,
                "headers": {},
                "html": "",
                "length": 0,
                "json": None,
                "elapsed": 0.0,
            }

        future = Future()
        self._queue.put((url, future))
        return future.result()

    def close(self):
        if self._stopped:
            return

        self._stopped = True
        self._queue.put(None)
        if self._thread.is_alive():
            self._thread.join(timeout=5)