"""
============================================================
TraceLens Engine Profiler  (v2)
============================================================

Thread-safe instrumentation module.  Records timing for every stage of a
username investigation and prints a structured performance report at the end.

New in v2
---------
- Tracks browser worker pool metrics: workers, queue wait, context reuse,
  avg task duration, max simultaneous jobs.
- Reports browser_tasks_serialized=False when the new worker pool is active.
- Accepts start_investigation(browser_workers=N) to reflect pool size.

Author: TraceLens
"""

import time
import threading


class EngineProfiler:

    def __init__(self, username: str = ""):
        self.username = username
        self.start_time: float | None = None
        self.end_time: float | None = None

        # Per-site metrics  { site_name: metric_dict }
        self.site_metrics: dict = {}
        self.site_order: list[str] = []
        self._lock = threading.Lock()

        # Thread-pool concurrency tracking
        self.workers_created = 0
        self.browser_workers = 0
        self.max_concurrent_tasks = 0
        self.active_tasks = 0
        self._task_active_periods: list[tuple[float, float]] = []
        self.browser_tasks_serialized = False

        # Browser pool aggregate stats (filled by record_browser_pool_stats)
        self._browser_pool_stats: dict = {}

        # Browser reuse strategy label
        self.browser_reuse_strategy = "one browser globally (worker pool)"

        # Unnecessary wait warnings
        self.warnings: list[str] = []

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start_investigation(
        self,
        workers_created: int = 16,
        browser_workers: int = 4,
        browser_tasks_serialized: bool = False,
    ):
        self.start_time = time.perf_counter()
        self.workers_created = workers_created
        self.browser_workers = browser_workers
        self.browser_tasks_serialized = browser_tasks_serialized

    def end_investigation(self):
        self.end_time = time.perf_counter()

    # ------------------------------------------------------------------ #
    # Per-site recording
    # ------------------------------------------------------------------ #

    def record_site_metric(self, site_name: str, metric_data: dict):
        with self._lock:
            if site_name not in self.site_order:
                self.site_order.append(site_name)
            self.site_metrics[site_name] = metric_data

    def record_task_start(self):
        with self._lock:
            self.active_tasks += 1
            if self.active_tasks > self.max_concurrent_tasks:
                self.max_concurrent_tasks = self.active_tasks

    def record_task_end(self, start_t: float, end_t: float):
        with self._lock:
            self.active_tasks = max(0, self.active_tasks - 1)
            self._task_active_periods.append((start_t, end_t))

    def add_warning(self, message: str):
        with self._lock:
            self.warnings.append(message)

    def record_browser_pool_stats(self, stats: dict):
        """Call once after all browser jobs finish to store pool-level metrics."""
        with self._lock:
            self._browser_pool_stats = dict(stats)

    # ------------------------------------------------------------------ #
    # Derived metrics
    # ------------------------------------------------------------------ #

    def calculate_utilization(self, total_investigation_time: float) -> float:
        if not self._task_active_periods or total_investigation_time <= 0 or self.workers_created <= 0:
            return 0.0
        total_worker_time = sum(e - s for s, e in self._task_active_periods)
        max_capacity = total_investigation_time * self.workers_created
        return round((total_worker_time / max_capacity) * 100, 1)

    # ------------------------------------------------------------------ #
    # Report generation
    # ------------------------------------------------------------------ #

    def generate_report(self) -> str:
        total_time = (
            (self.end_time - self.start_time)
            if (self.start_time and self.end_time)
            else 0.0
        )

        lines: list[str] = []
        sep = "=" * 50
        thin = "-" * 30

        lines += [sep, "TraceLens Performance Report", sep, "", f"Total Investigation: {total_time:.2f} s", ""]

        slowest: list[tuple[str, float]] = []

        # ── Per-site details ──────────────────────────────────────────
        for site_name in self.site_order:
            m = self.site_metrics.get(site_name, {})
            total_site = m.get("total_time", 0.0)
            transport_type = m.get("transport_type", "requests")
            slowest.append((site_name, total_site))

            lines.append(site_name)
            if transport_type == "browser":
                qw = m.get("queue_wait", 0.0)
                wi = m.get("worker_id")
                worker_label = f"  [worker {wi}]" if wi is not None else ""
                lines.append(f"    Queue wait      : {qw:.2f} s{worker_label}")
                lines.append(f"    Browser Startup : {m.get('browser_startup', 0.0):.2f} s")
                lines.append(f"    New Page        : {m.get('new_page', 0.0):.2f} s")
                lines.append(f"    goto()          : {m.get('goto', 0.0):.2f} s")
                lines.append(f"    wait_for_load   : {m.get('wait_for_load', 0.0):.2f} s")
                lines.append(f"    popup dismiss   : {m.get('popup_dismiss', 0.0):.2f} s")
                lines.append(f"    html extraction : {m.get('html_extraction', 0.0):.2f} s")
                lines.append(f"    Detector        : {m.get('detector_time', 0.0):.2f} s")
                lines.append(f"    Total           : {total_site:.2f} s")
            else:
                lines.append(f"    Transport: {m.get('transport_time', 0.0):.2f} s")
                lines.append(f"    Detector : {m.get('detector_time', 0.0):.2f} s")
                lines.append(f"    Total    : {total_site:.2f} s")
            lines.append("")

        # ── Slowest Sites ─────────────────────────────────────────────
        slowest.sort(key=lambda x: x[1], reverse=True)
        lines += ["Slowest Sites", ""]
        for idx, (name, t) in enumerate(slowest[:5], 1):
            lines.append(f"{idx}. {name:<15} {t:.2f} s")
        lines.append("")

        # ── Unnecessary Wait Warnings ─────────────────────────────────
        if self.warnings:
            lines += ["Unnecessary Waits Detected", thin]
            for w in self.warnings:
                lines += ["WARNING:", w]
            lines.append("")

        # ── Concurrency Verification ──────────────────────────────────
        avg_util = self.calculate_utilization(total_time)
        lines += ["Concurrency Verification", thin]
        lines.append(f"Workers created         : {self.workers_created}")
        lines.append(f"Browser pool workers    : {self.browser_workers}")
        lines.append(f"Tasks running sim.      : {self.active_tasks}")
        lines.append(f"Maximum concurrent tasks: {self.max_concurrent_tasks}")
        lines.append(f"Average worker util.    : {avg_util}%")
        if self.browser_tasks_serialized:
            lines.append("NOTE: Browser tasks are serialized (single worker thread).")
        else:
            lines.append("OK  : Browser tasks execute concurrently via worker pool.")
        lines.append("")

        # ── Browser Worker Pool Stats ─────────────────────────────────
        bp = self._browser_pool_stats
        if bp:
            lines += ["Browser Worker Pool", thin]
            lines.append(f"Workers                 : {bp.get('num_workers', self.browser_workers)}")
            lines.append(f"Max simultaneous jobs   : {bp.get('max_simultaneous', 0)}")
            lines.append(f"Avg queue wait          : {bp.get('avg_queue_wait', 0.0):.2f} s")
            lines.append(f"Avg task time           : {bp.get('avg_task_time', 0.0):.2f} s")
            lines.append(f"Context reuse count     : {bp.get('context_reuse_count', 0)}")
            lines.append(f"Total browser tasks     : {bp.get('total_tasks', 0)}")
            lines.append("")

        # ── Browser Reuse Strategy ────────────────────────────────────
        lines += ["Browser Reuse Strategy", thin]
        lines.append(f"Strategy: {self.browser_reuse_strategy}")
        lines.append("")

        # ── Timeout Statistics ────────────────────────────────────────
        lines += ["Timeout Statistics", thin]
        for site_name in self.site_order:
            m = self.site_metrics.get(site_name, {})
            cfg = m.get("configured_timeout", 5)
            actual = m.get("total_time", 0.0)
            timed_out = "yes" if m.get("timed_out", False) else "no"
            lines.append(f"{site_name:<16} Configured: {cfg}s | Actual: {actual:.2f}s | Timed out: {timed_out}")
        lines.append("")

        # ── Optimization Opportunities ────────────────────────────────
        lines += ["Optimization Opportunities", thin]
        optimizations: list[tuple[str, str]] = []

        fixed_wait_gain = sum(m.get("fixed_wait_gain", 0.0) for m in self.site_metrics.values())
        if fixed_wait_gain > 0.3:
            optimizations.append(("Remove fixed popup timeout", f"{fixed_wait_gain:.1f} s"))

        ctx_gain = sum(
            m.get("new_page", 0.0)
            for m in self.site_metrics.values()
            if m.get("transport_type") == "browser"
        )
        if ctx_gain > 0.1:
            optimizations.append(("Reuse browser context (already applied)", f"~{ctx_gain:.1f} s saved"))

        wait_load_gain = sum(
            m.get("wait_for_load", 0.0)
            for m in self.site_metrics.values()
            if m.get("transport_type") == "browser"
        )
        if wait_load_gain > 0.2:
            optimizations.append(("Shorten networkidle wait", f"{wait_load_gain:.1f} s"))

        if self.browser_tasks_serialized:
            browser_total = sum(
                m.get("total_time", 0.0)
                for m in self.site_metrics.values()
                if m.get("transport_type") == "browser"
            )
            if browser_total > 2.0:
                est_min = max(1.0, round(browser_total * 0.4, 1))
                est_max = max(est_min + 1.0, round(browser_total * 0.7, 1))
                optimizations.append(("Parallelize browser tasks", f"{est_min}-{est_max} s"))
        else:
            # Pool is running — highlight any remaining slow sites
            slow_browser = [
                (name, m.get("total_time", 0.0))
                for name, m in self.site_metrics.items()
                if m.get("transport_type") == "browser" and m.get("total_time", 0.0) > 10
            ]
            for name, t in slow_browser:
                optimizations.append((
                    f"Investigate {name} timeout ({t:.0f}s) -- possible anti-bot",
                    "site-specific fix needed",
                ))

        if not optimizations:
            optimizations.append(("No significant bottlenecks identified", "--"))

        for title, gain in optimizations:
            lines.append(f"[+] {title}")
            lines.append(f"    Estimated gain: {gain}")
            lines.append("")

        lines.append(sep)
        return "\n".join(lines)

    def print_report(self) -> str:
        report_text = self.generate_report()
        try:
            print(report_text)
        except UnicodeEncodeError:
            import sys
            sys.stdout.buffer.write(report_text.encode("utf-8", errors="replace"))
            sys.stdout.buffer.write(b"\n")
            sys.stdout.buffer.flush()
        return report_text
