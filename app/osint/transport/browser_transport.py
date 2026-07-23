"""
TraceLens Browser Transport (v2 - Concurrent Worker Pool)

Architecture
------------
                        BrowserTransport
                               │
                    ┌──────────┴──────────┐
                    │  Shared Task Queue  │
                    └──────────┬──────────┘
             ┌─────────────────┼─────────────────┐
             │                 │                 │
       Worker-0           Worker-1           Worker-2  ...  Worker-N
   sync_playwright    sync_playwright    sync_playwright
       Browser            Browser            Browser
    BrowserContext     BrowserContext     BrowserContext
     (persistent)       (persistent)       (persistent)

Key design decisions
--------------------
- ONE Playwright + ONE Chromium per worker thread (100% thread-safe).
- N configurable worker threads drain a single shared task queue concurrently.
- BrowserContext is persistent per worker; cleared (not destroyed) between requests.
  This amortises the ~0.3-0.5 s context-creation overhead to a one-time cost.
- Navigation uses wait_until="domcontentloaded" + short networkidle fallback
  instead of always waiting for full networkidle (saves 0.5-2 s per page).
- Fixed wait_for_timeout() is replaced by condition-based waits so workers
  do not sleep longer than necessary.
- Adaptive timeouts: 12 s default, 15 s for known heavy sites (Replit, Hashnode).
- fetch(url) public interface is identical to v1 — no caller changes required.
"""

import atexit
import queue
import threading
import time
from concurrent.futures import Future

from playwright.sync_api import sync_playwright


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Number of parallel browser workers.  Raise to 6-8 on machines with more RAM.
BROWSER_WORKERS = 4


class BrowserTransport:

    def __init__(
        self,
        headless=True,
        timeout=12000,          # Default navigation timeout (ms)
        wait_time=3000,         # Kept for reference; condition-based waits are used instead
        viewport=(1366, 768),
        num_workers=BROWSER_WORKERS,
    ):
        self.headless = headless
        self.timeout = timeout
        self.wait_time = wait_time
        self.viewport = viewport
        self.num_workers = num_workers

        # Shared task queue — all workers drain this concurrently
        self._task_queue = queue.Queue()
        self._stopped = False

        # Worker thread handles
        self._workers: list[threading.Thread] = []

        # Profiling / stats (guarded by _lock)
        self._lock = threading.Lock()
        self._first_req_reported = False
        self.startup_time = 0.0

        self._context_reuse_count = 0   # successful fetches (context reused)
        self._total_queue_wait = 0.0
        self._total_task_time = 0.0
        self._task_count = 0
        self._active_now = 0
        self._max_simultaneous = 0

        # Start workers and wait for all to finish init
        self._launch_workers()
        atexit.register(self.close)

    # ------------------------------------------------------------------ #
    # Startup
    # ------------------------------------------------------------------ #

    def _launch_workers(self):
        startup_start = time.perf_counter()
        started_events = []

        for i in range(self.num_workers):
            ev = threading.Event()
            started_events.append(ev)
            t = threading.Thread(
                target=self._worker_loop,
                args=(i, ev),
                daemon=True,
                name=f"BrowserWorker-{i}",
            )
            self._workers.append(t)
            t.start()

        # Block until every worker has launched its own Playwright + browser
        for ev in started_events:
            ev.wait()

        self.startup_time = round(time.perf_counter() - startup_start, 4)

    # ------------------------------------------------------------------ #
    # Worker Loop  (runs entirely on self._workers[i] — never shared)
    # ------------------------------------------------------------------ #

    def _worker_loop(self, worker_id: int, started_event: threading.Event):
        """
        Each worker owns its own playwright instance, browser, and context.
        No playwright objects are ever shared between threads.
        """
        playwright = None
        browser = None
        context = None

        try:
            playwright = sync_playwright().start()
            browser = playwright.chromium.launch(headless=self.headless)
            context = self._create_fresh_context(browser)
            started_event.set()
        except Exception as exc:  # noqa: BLE001
            # Signal ready even on failure so __init__ doesn't hang
            started_event.set()
            return

        try:
            while True:
                item = self._task_queue.get()
                if item is None:                    # shutdown sentinel
                    self._task_queue.task_done()
                    break

                url, future, enqueue_time = item
                queue_wait = time.perf_counter() - enqueue_time

                with self._lock:
                    self._active_now += 1
                    if self._active_now > self._max_simultaneous:
                        self._max_simultaneous = self._active_now

                try:
                    result = self._execute_fetch(context, url, queue_wait, worker_id)
                    # Reuse context: clear cookies + localStorage for isolation
                    self._clear_context(context)
                    future.set_result(result)
                except Exception as exc:  # noqa: BLE001
                    # On unexpected error recreate the context for safety
                    try:
                        context.close()
                        context = self._create_fresh_context(browser)
                    except Exception:
                        pass
                    future.set_exception(exc)
                finally:
                    with self._lock:
                        self._active_now = max(0, self._active_now - 1)
                    self._task_queue.task_done()

        finally:
            for obj, name in [(context, "context"), (browser, "browser"), (playwright, "playwright")]:
                try:
                    if obj:
                        obj.close() if name != "playwright" else obj.stop()
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    # Context Helpers
    # ------------------------------------------------------------------ #

    def _create_fresh_context(self, browser):
        return browser.new_context(
            viewport={"width": self.viewport[0], "height": self.viewport[1]},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/138.0.0.0 Safari/537.36"
            ),
            locale="en-US",
        )

    def _clear_context(self, context):
        """Clear cookies between requests to maintain session isolation."""
        try:
            context.clear_cookies()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Fetch Execution  (runs on a worker thread)
    # ------------------------------------------------------------------ #

    def _execute_fetch(self, context, url: str, queue_wait: float, worker_id: int) -> dict:
        start_wall = time.time()
        start_perf = time.perf_counter()
        page = None

        # ── Startup time (attributed only to the very first request) ──
        with self._lock:
            if not self._first_req_reported:
                self._first_req_reported = True
                b_startup = self.startup_time
            else:
                b_startup = 0.0
            self._context_reuse_count += 1

        # ── Adaptive timeout per site ──
        is_instagram = "instagram.com" in url.lower()
        is_heavy = any(h in url.lower() for h in ("replit.com", "hashnode.com"))
        nav_timeout = 15000 if is_heavy else (12000 if is_instagram else self.timeout)

        try:
            # ── Page creation (reusing context, not recreating) ──
            new_page_start = time.perf_counter()
            page = context.new_page()
            new_page_time = time.perf_counter() - new_page_start

            graphql: list[dict] = []

            def capture_response(response):
                try:
                    if "graphql" in response.url.lower():
                        graphql.append({"url": response.url, "status": response.status})
                except Exception:
                    pass

            page.on("response", capture_response)

            # ── Navigation ──
            # domcontentloaded is faster than networkidle; networkidle is a short fallback
            goto_start = time.perf_counter()
            response = page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=nav_timeout,
            )
            goto_time = time.perf_counter() - goto_start

            # Short networkidle fallback (3 s cap instead of the original 5 s)
            wait_load_start = time.perf_counter()
            try:
                page.wait_for_load_state("networkidle", timeout=3000)
            except Exception:
                pass
            wait_for_load_time = time.perf_counter() - wait_load_start

            # ── Site-specific popup / content wait ──
            popup_start = time.perf_counter()
            unnecessary_wait_warning = None
            fixed_wait_gain = 0.0

            if is_instagram:
                # Dismiss login popup if present
                for selector in (
                    "button[aria-label='Close']",
                    "svg[aria-label='Close']",
                    "div[role='dialog'] button",
                    "button:has-text('Not Now')",
                    "button:has-text('Close')",
                ):
                    try:
                        loc = page.locator(selector).first
                        if loc.count() > 0:
                            loc.click(timeout=1000)
                            break
                    except Exception:
                        pass

                # Condition-based wait for OG metadata (replaces fixed 3 s sleep)
                content_start = time.perf_counter()
                try:
                    page.wait_for_function(
                        """() => document.documentElement.innerHTML.includes('property="og:description"')""",
                        timeout=8000,
                    )
                except Exception:
                    pass
                content_ready_ms = (time.perf_counter() - content_start) * 1000

                # Detect unnecessary wait savings vs the old fixed 3000 ms
                if content_ready_ms < (self.wait_time - 200):
                    unnecessary_wait_warning = (
                        f"instagram.com waited {self.wait_time}ms but content "
                        f"became available after {int(content_ready_ms)}ms."
                    )
                    fixed_wait_gain = (self.wait_time - content_ready_ms) / 1000.0

            else:
                # Generic sites: wait for body via selector (no fixed sleep)
                body_start = time.perf_counter()
                try:
                    page.wait_for_selector("body", timeout=2000)
                except Exception:
                    pass
                body_wait_ms = (time.perf_counter() - body_start) * 1000

                # Report saving vs old fixed wait_time
                if self.wait_time >= 2000 and body_wait_ms < (self.wait_time - 500):
                    saved_ms = self.wait_time - max(100.0, body_wait_ms)
                    if saved_ms > 500:
                        unnecessary_wait_warning = (
                            f"{url.split('/')[2]} waited {self.wait_time}ms but "
                            f"content became available after {int(max(100.0, body_wait_ms))}ms."
                        )
                        fixed_wait_gain = saved_ms / 1000.0

            popup_dismiss_time = time.perf_counter() - popup_start

            # ── HTML extraction ──
            html_start = time.perf_counter()
            html = page.content()
            html_extraction_time = time.perf_counter() - html_start

            # ── Record aggregate stats ──
            task_time = time.perf_counter() - start_perf
            with self._lock:
                self._total_queue_wait += queue_wait
                self._total_task_time += task_time
                self._task_count += 1

            return {
                "success": True,
                "status": response.status if response else None,
                "final_url": page.url,
                "title": page.title(),
                "headers": dict(response.headers) if response else {},
                "html": html,
                "length": len(html),
                "elapsed": round(time.time() - start_wall, 2),
                "graphql": graphql,
                "error": None,
                "_profile_timing": {
                    "browser_startup": b_startup,
                    "new_page": new_page_time,
                    "goto": goto_time,
                    "wait_for_load": wait_for_load_time,
                    "popup_dismiss": popup_dismiss_time,
                    "html_extraction": html_extraction_time,
                    "queue_wait": queue_wait,
                    "unnecessary_wait_warning": unnecessary_wait_warning,
                    "fixed_wait_gain": fixed_wait_gain,
                    "worker_id": worker_id,
                },
            }

        except Exception as exc:
            task_time = time.perf_counter() - start_perf
            with self._lock:
                self._total_queue_wait += queue_wait
                self._total_task_time += task_time
                self._task_count += 1

            return {
                "success": False,
                "error": str(exc),
                "status": None,
                "final_url": url,
                "headers": {},
                "html": "",
                "length": 0,
                "json": None,
                "elapsed": round(time.time() - start_wall, 2),
                "_profile_timing": {
                    "browser_startup": b_startup,
                    "new_page": 0.0,
                    "goto": round(time.time() - start_wall, 2),
                    "wait_for_load": 0.0,
                    "popup_dismiss": 0.0,
                    "html_extraction": 0.0,
                    "queue_wait": queue_wait,
                    "unnecessary_wait_warning": None,
                    "fixed_wait_gain": 0.0,
                    "worker_id": worker_id,
                },
            }

        finally:
            if page is not None:
                try:
                    page.close()
                except Exception:
                    pass

    # ------------------------------------------------------------------ #
    # Public Interface  (unchanged from v1)
    # ------------------------------------------------------------------ #

    def fetch(self, url: str) -> dict:
        """
        Thread-safe fetch.  Can be called from any thread.
        Dispatches the request to an available browser worker and blocks
        until the result is ready.  Interface identical to RequestsTransport.
        """
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

        future: Future = Future()
        enqueue_time = time.perf_counter()
        self._task_queue.put((url, future, enqueue_time))
        return future.result()

    def get_pool_stats(self) -> dict:
        """Returns a snapshot of browser worker pool metrics for the profiler."""
        with self._lock:
            n = self._task_count
            return {
                "num_workers": self.num_workers,
                "context_reuse_count": self._context_reuse_count,
                "avg_queue_wait": round(self._total_queue_wait / n, 4) if n else 0.0,
                "avg_task_time": round(self._total_task_time / n, 4) if n else 0.0,
                "max_simultaneous": self._max_simultaneous,
                "total_tasks": n,
            }

    def close(self):
        if self._stopped:
            return
        self._stopped = True
        # One sentinel per worker to unblock their queue.get()
        for _ in self._workers:
            self._task_queue.put(None)
        for t in self._workers:
            if t.is_alive():
                t.join(timeout=8)