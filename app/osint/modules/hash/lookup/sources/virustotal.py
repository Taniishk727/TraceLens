"""Optional VirusTotal Public API file-report lookup (requires an API key)."""

import os
import threading
import time
from collections import deque
from typing import List, Optional

from app.osint.core.transport.requests_transport import RequestsTransport
from app.osint.modules.hash.lookup.base import BaseLookupSource
from app.osint.modules.hash.lookup.models import LookupResult, LookupSourceCapability, LookupStatus


class VirusTotalSource(BaseLookupSource):
    BASE_URL = "https://www.virustotal.com/api/v3/files/{}"
    DOCS_URL = "https://docs.virustotal.com/reference/file-info"
    _request_times: deque[float] = deque()
    _rate_lock = threading.Lock()

    def __init__(self, timeout: float = 8.0, transport: Optional[RequestsTransport] = None):
        super().__init__(timeout=timeout)
        self.transport = transport or RequestsTransport(timeout=timeout)

    @property
    def capability(self) -> LookupSourceCapability:
        return LookupSourceCapability(
            name="VirusTotal",
            slug="virustotal",
            supported_algorithms=["MD5", "SHA-1", "SHA-256"],
            documentation_url=self.DOCS_URL,
            supports_plaintext_lookup=False,
            is_active=bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip()),
        )

    @classmethod
    def _take_rate_slot(cls) -> bool:
        now = time.monotonic()
        with cls._rate_lock:
            while cls._request_times and now - cls._request_times[0] >= 60:
                cls._request_times.popleft()
            if len(cls._request_times) >= 4:
                return False
            cls._request_times.append(now)
            return True

    def lookup(self, hash_value: str, possible_algorithms: Optional[List[str]] = None) -> LookupResult:
        started = time.perf_counter()
        key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
        if not key:
            return LookupResult(
                status=LookupStatus.SOURCE_UNAVAILABLE,
                source=self.capability.name,
                source_url=self.DOCS_URL,
                details=["Set VIRUSTOTAL_API_KEY to enable VirusTotal lookups."],
            )
        supported = {"MD5", "SHA-1", "SHA1", "SHA-256", "SHA256"}
        if possible_algorithms and not any(value.upper() in supported for value in possible_algorithms):
            return LookupResult(
                status=LookupStatus.UNSUPPORTED,
                source=self.capability.name,
                source_url=self.DOCS_URL,
                details=["VirusTotal file reports support MD5, SHA-1, and SHA-256 hashes."],
            )
        if not self._take_rate_slot():
            return LookupResult(
                status=LookupStatus.RATE_LIMITED,
                source=self.capability.name,
                source_url=self.DOCS_URL,
                details=["TraceLens limits VirusTotal Public API calls to four per minute."],
            )
        response = self.transport.fetch(
            self.BASE_URL.format(hash_value.strip().lower()),
            headers={"x-apikey": key, "Accept": "application/json"},
        )
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        if not response.get("success"):
            return LookupResult(status=LookupStatus.SOURCE_UNAVAILABLE, source=self.capability.name, source_url=self.DOCS_URL, details=[f"VirusTotal request failed: {response.get('error') or 'network error'}"], execution_time_ms=elapsed)
        status = response.get("status")
        if status == 404:
            return LookupResult(status=LookupStatus.NOT_FOUND, source=self.capability.name, source_url=self.DOCS_URL, details=["VirusTotal has no report for this file hash."], execution_time_ms=elapsed)
        if status == 429:
            return LookupResult(status=LookupStatus.RATE_LIMITED, source=self.capability.name, source_url=self.DOCS_URL, details=["VirusTotal rate limit reached."], execution_time_ms=elapsed)
        if status in (401, 403):
            return LookupResult(status=LookupStatus.SOURCE_UNAVAILABLE, source=self.capability.name, source_url=self.DOCS_URL, details=[f"VirusTotal rejected the API key or access (HTTP {status})."], execution_time_ms=elapsed)
        if status != 200:
            return LookupResult(status=LookupStatus.SOURCE_UNAVAILABLE, source=self.capability.name, source_url=self.DOCS_URL, details=[f"VirusTotal returned HTTP {status or 'unknown'}."], execution_time_ms=elapsed)

        body = response.get("json")
        attributes = body.get("data", {}).get("attributes", {}) if isinstance(body, dict) else {}
        if not isinstance(attributes, dict):
            return LookupResult(status=LookupStatus.ERROR, source=self.capability.name, source_url=self.DOCS_URL, details=["VirusTotal returned an invalid file record."], execution_time_ms=elapsed)
        stats = attributes.get("last_analysis_stats")
        metadata = {
            key: attributes[key]
            for key in ("type_description", "meaningful_name", "size", "reputation", "last_analysis_date")
            if attributes.get(key) is not None
        }
        if isinstance(stats, dict):
            metadata["last_analysis_stats"] = stats
        return LookupResult(
            status=LookupStatus.FOUND,
            source=self.capability.name,
            source_url=f"https://www.virustotal.com/gui/file/{hash_value.strip().lower()}",
            details=["VirusTotal has a file report. Detection counts are community signals, not a definitive verdict."],
            execution_time_ms=elapsed,
            metadata=metadata,
        )
