"""
============================================================
TraceLens Hash Lookup - HashToolkit Integration Source
============================================================

Public hash lookup source integrating with HashToolkit's public API endpoint.

Author:
    TraceLens
"""

import time
import urllib.parse
from typing import List, Optional
from app.osint.core.transport.requests_transport import RequestsTransport
from app.osint.modules.hash.lookup.base import BaseLookupSource
from app.osint.modules.hash.lookup.models import (
    LookupResult,
    LookupSourceCapability,
    LookupStatus,
)


class HashToolkitSource(BaseLookupSource):
    """
    Public hash lookup source for MD5, SHA-1, SHA-256, SHA-384, SHA-512 hashes.
    """

    BASE_URL = "https://hashtoolkit.com/api/hash"

    def __init__(self, timeout: float = 6.0, transport: Optional[RequestsTransport] = None):
        super().__init__(timeout=timeout)
        self.transport = transport or RequestsTransport(timeout=timeout)

    @property
    def capability(self) -> LookupSourceCapability:
        return LookupSourceCapability(
            name="HashToolkit",
            slug="hashtoolkit",
            supported_algorithms=["MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"],
            documentation_url="https://hashtoolkit.com",
            supports_batch=False,
            supports_plaintext_lookup=True,
            is_active=True,
        )

    def lookup(
        self, hash_value: str, possible_algorithms: Optional[List[str]] = None
    ) -> LookupResult:
        start_time = time.perf_counter()
        normalized_hash = hash_value.strip().lower()

        # Check if algorithm candidate list is compatible
        if possible_algorithms:
            supported_set = set(self.capability.supported_algorithms)
            if not any(algo in supported_set for algo in possible_algorithms):
                return LookupResult(
                    status=LookupStatus.UNSUPPORTED,
                    source=self.capability.name,
                    source_url=self.capability.documentation_url,
                    details=[
                        f"{self.capability.name} does not support looking up candidates: {', '.join(possible_algorithms)}."
                    ],
                    execution_time_ms=round((time.perf_counter() - start_time) * 1000, 2),
                )

        target_url = f"{self.BASE_URL}/{urllib.parse.quote(normalized_hash)}"

        res = self.transport.fetch(target_url)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if not res.get("success"):
            return LookupResult(
                status=LookupStatus.SOURCE_UNAVAILABLE,
                source=self.capability.name,
                source_url=self.capability.documentation_url,
                details=[f"Network error accessing {self.capability.name}: {res.get('error')}"],
                execution_time_ms=elapsed_ms,
            )

        status_code = res.get("status")
        html_content = res.get("html") or ""

        if status_code == 429:
            return LookupResult(
                status=LookupStatus.RATE_LIMITED,
                source=self.capability.name,
                source_url=self.capability.documentation_url,
                details=[f"Rate limit exceeded on {self.capability.name}."],
                execution_time_ms=elapsed_ms,
            )

        if status_code in (403, 404, 401) or "Cloudflare" in html_content or "Attention Required!" in html_content:
            return LookupResult(
                status=LookupStatus.SOURCE_UNAVAILABLE,
                source=self.capability.name,
                source_url=self.capability.documentation_url,
                details=[
                    f"{self.capability.name} returned HTTP {status_code or 403} (Cloudflare anti-bot verification or endpoint change).",
                    "Automated API lookup was unavailable or blocked by anti-bot protection."
                ],
                execution_time_ms=elapsed_ms,
            )

        if status_code and status_code >= 500:
            return LookupResult(
                status=LookupStatus.SOURCE_UNAVAILABLE,
                source=self.capability.name,
                source_url=self.capability.documentation_url,
                details=[f"{self.capability.name} server returned HTTP {status_code}."],
                execution_time_ms=elapsed_ms,
            )

        json_data = res.get("json")
        if isinstance(json_data, dict):
            # API returned JSON response
            plaintext = json_data.get("result") or json_data.get("plaintext") or json_data.get("text")
            algo = json_data.get("type") or json_data.get("algorithm")

            if plaintext:
                # Infer algorithm from candidates if API returned unknown or generic
                matched_algo = algo if algo else (possible_algorithms[0] if possible_algorithms else "Unknown")
                return LookupResult(
                    status=LookupStatus.FOUND,
                    plaintext=str(plaintext),
                    source=self.capability.name,
                    source_url=f"https://hashtoolkit.com/generate-hash/?text={urllib.parse.quote(str(plaintext))}",
                    algorithm=matched_algo,
                    details=[f"Exact plaintext match found on {self.capability.name}."],
                    execution_time_ms=elapsed_ms,
                )

        # Handle HTML response parsing if API returned 200 HTML page
        html_content = res.get("html") or ""
        if "res-text" in html_content or "span class=\"text\"" in html_content:
            import re
            match = re.search(r'<span class="text"[^>]*>(.*?)</span>', html_content, re.IGNORECASE)
            if match:
                pt = match.group(1).strip()
                matched_algo = possible_algorithms[0] if possible_algorithms else "Unknown"
                return LookupResult(
                    status=LookupStatus.FOUND,
                    plaintext=pt,
                    source=self.capability.name,
                    source_url=f"https://hashtoolkit.com/reverse-hash/?hash={normalized_hash}",
                    algorithm=matched_algo,
                    details=[f"Exact plaintext match found on {self.capability.name}."],
                    execution_time_ms=elapsed_ms,
                )

        return LookupResult(
            status=LookupStatus.NOT_FOUND,
            source=self.capability.name,
            source_url=self.capability.documentation_url,
            details=[f"No matching plaintext found on {self.capability.name}."],
            execution_time_ms=elapsed_ms,
        )
