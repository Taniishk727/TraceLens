"""Keyless lookups against CIRCL's catalog of known files (including NSRL)."""

import time
from typing import List, Optional

from app.osint.core.transport.requests_transport import RequestsTransport
from app.osint.modules.hash.lookup.base import BaseLookupSource
from app.osint.modules.hash.lookup.models import LookupResult, LookupSourceCapability, LookupStatus


class CIRCLHashlookupSource(BaseLookupSource):
    BASE_URL = "https://hashlookup.circl.lu/lookup"
    DOCS_URL = "https://circl.lu/services/hashlookup/"
    ALGORITHMS = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256"}

    def __init__(self, timeout: float = 6.0, transport: Optional[RequestsTransport] = None):
        super().__init__(timeout=timeout)
        self.transport = transport or RequestsTransport(timeout=timeout)

    @property
    def capability(self) -> LookupSourceCapability:
        return LookupSourceCapability(
            name="CIRCL hashlookup",
            slug="circl-hashlookup",
            supported_algorithms=list(self.ALGORITHMS),
            documentation_url=self.DOCS_URL,
            supports_plaintext_lookup=False,
            is_active=True,
        )

    def lookup(self, hash_value: str, possible_algorithms: Optional[List[str]] = None) -> LookupResult:
        started = time.perf_counter()
        candidates = {value.upper().replace("SHA1", "SHA-1").replace("SHA256", "SHA-256") for value in (possible_algorithms or [])}
        algorithm = next((name for name in self.ALGORITHMS if name in candidates), None)
        if algorithm is None:
            return LookupResult(
                status=LookupStatus.UNSUPPORTED,
                source=self.capability.name,
                source_url=self.DOCS_URL,
                details=["CIRCL hashlookup supports MD5, SHA-1, and SHA-256 file hashes."],
            )

        response = self.transport.fetch(
            f"{self.BASE_URL}/{self.ALGORITHMS[algorithm]}/{hash_value.strip().lower()}",
            headers={"Accept": "application/json"},
        )
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        if not response.get("success"):
            return LookupResult(
                status=LookupStatus.SOURCE_UNAVAILABLE,
                source=self.capability.name,
                source_url=self.DOCS_URL,
                details=[f"CIRCL hashlookup request failed: {response.get('error') or 'network error'}"],
                execution_time_ms=elapsed,
            )
        status = response.get("status")
        if status == 404:
            return LookupResult(status=LookupStatus.NOT_FOUND, source=self.capability.name, source_url=self.DOCS_URL, details=["No catalogued file matched this hash."], execution_time_ms=elapsed)
        if status == 429:
            return LookupResult(status=LookupStatus.RATE_LIMITED, source=self.capability.name, source_url=self.DOCS_URL, details=["CIRCL hashlookup rate limit reached."], execution_time_ms=elapsed)
        if status != 200:
            return LookupResult(status=LookupStatus.SOURCE_UNAVAILABLE, source=self.capability.name, source_url=self.DOCS_URL, details=[f"CIRCL hashlookup returned HTTP {status or 'unknown'}."], execution_time_ms=elapsed)

        record = response.get("json")
        if not isinstance(record, dict):
            return LookupResult(status=LookupStatus.ERROR, source=self.capability.name, source_url=self.DOCS_URL, details=["CIRCL returned an invalid JSON record."], execution_time_ms=elapsed)
        useful = {
            key: record[key]
            for key in ("FileName", "FileSize", "ProductName", "ProductVersion", "PackageName", "PackageVersion", "source", "db", "hashlookup:trust")
            if record.get(key) not in (None, "")
        }
        return LookupResult(
            status=LookupStatus.FOUND,
            source=self.capability.name,
            source_url=self.DOCS_URL,
            algorithm=algorithm,
            details=["Hash matched a catalogued file. A catalog match is not a safety verdict."],
            execution_time_ms=elapsed,
            metadata={"record": useful},
        )
