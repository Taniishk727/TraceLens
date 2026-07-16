"""
TraceLens Username Investigation Module (Version 3)
Dispatcher-based architecture.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import requests

from app.osint.data.username_sites import SITES
from app.osint.detectors.registry import get_detector


MAX_WORKERS = min(16, len(SITES))


STATUS_PRIORITY = {
    "Found": 0,
    "Unknown": 1,
    "Timeout": 2,
    "Error": 3,
    "Not Found": 4,
}


def run_detector(session, site, username):
    detector_name = site.get("detector")

    detector = get_detector(detector_name)

    if detector is None:
        return {
            "site": site["name"],
            "category": site.get("category", "Unknown"),
            "url": site["url"].format(username),
            "status": "Unsupported Detector",
            "status_code": None,
            "confidence": 0,
            "response_time": 0,
            "detector": detector_name,
            "error": f"Detector '{detector_name}' is not registered."
        }

    return detector(site=site, username=username, session=session)


def investigate(username):
    start = time.perf_counter()

    profiles = []

    session = requests.Session()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [
                executor.submit(run_detector, session, site, username)
                for site in SITES
            ]

            for future in as_completed(futures):
                profiles.append(future.result())
    finally:
        session.close()

    profiles.sort(
        key=lambda p: (
            STATUS_PRIORITY.get(p["status"], 99),
            p["site"]
        )
    )

    summary = {
        "total_sites": len(SITES),
        "found": sum(p["status"] == "Found" for p in profiles),
        "not_found": sum(p["status"] == "Not Found" for p in profiles),
        "errors": sum(p["status"] in ("Error", "Timeout") for p in profiles),
    }

    metadata = {
        "execution_time": round((time.perf_counter() - start) * 1000, 2),
        "scan_method": "Concurrent",
        "threads": MAX_WORKERS,
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
