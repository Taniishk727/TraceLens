"""
TraceLens Username Investigation Module (Version 4)

Architecture changes from v3
-----------------------------
- All sites (requests + browser) are submitted into ONE ThreadPoolExecutor.
  Previously, browser sites ran in a serial loop *after* the executor finished,
  adding every browser site's time sequentially to the wall-clock total.
- BrowserTransport v2 exposes a thread-safe fetch() backed by a worker pool,
  so calling it from multiple executor threads concurrently is safe and fast.
- Profiler is updated to report browser_tasks_serialized=False and to collect
  the new browser pool statistics at the end of the investigation.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from app.osint.transport.requests_transport import RequestsTransport
from app.osint.transport.browser_transport import BrowserTransport
from app.osint.data.username_sites import SITES
from app.osint.detectors.registry import get_detector
from app.osint.profiler import EngineProfiler


# One shared instance per process — browser workers stay alive across investigations.
MAX_WORKERS = min(16, len(SITES))
REQUESTS_TRANSPORT = RequestsTransport()
BROWSER_TRANSPORT = BrowserTransport()


STATUS_PRIORITY = {
    "Found": 0,
    "Unknown": 1,
    "Timeout": 2,
    "Error": 3,
    "Not Found": 4,
}


# ---------------------------------------------------------------------------
# Transport profiling wrapper
# ---------------------------------------------------------------------------

class TransportProfilerWrapper:
    """
    Thin wrapper around a transport that captures the round-trip time and the
    raw response (including _profile_timing) for downstream profiling.
    """
    def __init__(self, target_transport):
        self._target = target_transport
        self.last_fetch_info: dict = {}

    def fetch(self, url: str) -> dict:
        t0 = time.perf_counter()
        resp = self._target.fetch(url)
        t1 = time.perf_counter()
        self.last_fetch_info = {
            "transport_time": t1 - t0,
            "response": resp,
        }
        return resp

    def __getattr__(self, name):
        return getattr(self._target, name)


# ---------------------------------------------------------------------------
# Per-site detector runner
# ---------------------------------------------------------------------------

def run_detector(site: dict, username: str, profiler: EngineProfiler | None = None) -> dict:
    t_start = time.perf_counter()

    if profiler:
        profiler.record_task_start()

    detector_name = site.get("detector")
    detector = get_detector(detector_name)

    if detector is None:
        result = {
            "site": site["name"],
            "category": site.get("category", "Unknown"),
            "url": site["url"].format(username),
            "status": "Unsupported Detector",
            "status_code": None,
            "confidence": 0,
            "response_time": 0,
            "detector": detector_name,
            "error": f"Detector '{detector_name}' is not registered.",
        }
        if profiler:
            t_end = time.perf_counter()
            profiler.record_task_end(t_start, t_end)
            profiler.record_site_metric(site["name"], {
                "total_time": t_end - t_start,
                "transport_time": 0.0,
                "detector_time": t_end - t_start,
                "transport_type": site.get("transport", "requests"),
                "configured_timeout": site.get("timeout", 5),
                "timed_out": False,
            })
        return result

    transport_name = site.get("transport", "requests")
    transport = BROWSER_TRANSPORT if transport_name == "browser" else REQUESTS_TRANSPORT

    wrapper = TransportProfilerWrapper(transport)
    result = detector(site=site, username=username, transport=wrapper)

    t_end = time.perf_counter()
    total_site_time = t_end - t_start

    if profiler:
        profiler.record_task_end(t_start, t_end)

        last_info = wrapper.last_fetch_info
        transport_time = last_info.get("transport_time", 0.0)
        detector_time = max(0.0, total_site_time - transport_time)

        resp = last_info.get("response", {})
        pt = resp.get("_profile_timing", {}) if isinstance(resp, dict) else {}

        if pt.get("unnecessary_wait_warning"):
            profiler.add_warning(pt["unnecessary_wait_warning"])

        is_timed_out = (
            result.get("status") == "Timeout"
            or "timeout" in str(result.get("error", "")).lower()
        )

        profiler.record_site_metric(site["name"], {
            "total_time": total_site_time,
            "transport_time": transport_time,
            "detector_time": detector_time,
            "transport_type": transport_name,
            # Browser-specific stage timings (0.0 for requests-based sites)
            "browser_startup": pt.get("browser_startup", 0.0),
            "new_page": pt.get("new_page", 0.0),
            "goto": pt.get("goto", 0.0),
            "wait_for_load": pt.get("wait_for_load", 0.0),
            "popup_dismiss": pt.get("popup_dismiss", 0.0),
            "html_extraction": pt.get("html_extraction", 0.0),
            "queue_wait": pt.get("queue_wait", 0.0),
            "fixed_wait_gain": pt.get("fixed_wait_gain", 0.0),
            "worker_id": pt.get("worker_id"),
            "configured_timeout": site.get("timeout", 5),
            "timed_out": is_timed_out,
        })

    return result


# ---------------------------------------------------------------------------
# Main investigation entry-point
# ---------------------------------------------------------------------------

def investigate(username: str) -> dict:
    profiler = EngineProfiler(username=username)

    # BrowserTransport v2 runs a parallel worker pool internally — no serialization.
    profiler.start_investigation(
        workers_created=MAX_WORKERS,
        browser_workers=BROWSER_TRANSPORT.num_workers,
        browser_tasks_serialized=False,
    )

    start = time.perf_counter()
    profiles = []

    # Submit ALL sites (requests + browser) into the same executor.
    # BrowserTransport.fetch() is thread-safe: any thread can call it;
    # it dispatches to an internal worker pool and blocks until complete.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(run_detector, site, username, profiler)
            for site in SITES
        ]
        for future in as_completed(futures):
            profiles.append(future.result())

    # Collect browser pool statistics from the transport after all jobs finish
    profiler.record_browser_pool_stats(BROWSER_TRANSPORT.get_pool_stats())
    profiler.end_investigation()

    # Print the performance report to stdout
    profiler.print_report()

    profiles.sort(
        key=lambda p: (STATUS_PRIORITY.get(p["status"], 99), p["site"])
    )

    summary = {
        "total_sites": len(SITES),
        "found": sum(p["status"] == "Found" for p in profiles),
        "not_found": sum(p["status"] == "Not Found" for p in profiles),
        "errors": sum(p["status"] in ("Error", "Timeout") for p in profiles),
    }

    metadata = {
        "execution_time": round((time.perf_counter() - start) * 1000, 2),
        "scan_method": "Concurrent (unified pool)",
        "threads": MAX_WORKERS,
        "browser_workers": BROWSER_TRANSPORT.num_workers,
        "sites_checked": len(SITES),
    }

    return {
        "module": "Username Investigation",
        "status": "completed",
        "username": username,
        "summary": summary,
        "metadata": metadata,
        "profiles": profiles,
    }
