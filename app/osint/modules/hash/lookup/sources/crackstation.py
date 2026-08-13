"""
============================================================
TraceLens Hash Lookup - CrackStation Integration Stub
============================================================

Public hash lookup source architecture stub for CrackStation.
Complies strictly with bot/CAPTCHA protection guidelines by failing
gracefully with SOURCE_UNAVAILABLE and offering manual lookup links.

Author:
    TraceLens
"""

import time
from typing import List, Optional
from app.osint.modules.hash.lookup.base import BaseLookupSource
from app.osint.modules.hash.lookup.models import (
    LookupResult,
    LookupSourceCapability,
    LookupStatus,
)


class CrackStationSource(BaseLookupSource):
    """
    CrackStation public hash lookup capability stub.
    Does NOT bypass CAPTCHA or anti-bot protections.
    """

    DOCUMENTATION_URL = "https://crackstation.net"

    @property
    def capability(self) -> LookupSourceCapability:
        return LookupSourceCapability(
            name="CrackStation",
            slug="crackstation",
            supported_algorithms=[
                "LM", "NTLM", "md2", "md4", "MD5", "sha1",
                "sha224", "SHA-256", "sha384", "SHA-512", "ripemd160"
            ],
            documentation_url=self.DOCUMENTATION_URL,
            supports_batch=False,
            supports_plaintext_lookup=True,
            is_active=False,  # Set false to prevent automated CAPTCHA triggers
        )

    def lookup(
        self, hash_value: str, possible_algorithms: Optional[List[str]] = None
    ) -> LookupResult:
        start_time = time.perf_counter()
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # CrackStation requires interactive CAPTCHA verification. Return SOURCE_UNAVAILABLE with manual link.
        return LookupResult(
            status=LookupStatus.SOURCE_UNAVAILABLE,
            source=self.capability.name,
            source_url=self.DOCUMENTATION_URL,
            details=[
                "CrackStation requires interactive CAPTCHA verification for automated queries.",
                "Use manual investigation link if needed."
            ],
            execution_time_ms=elapsed_ms,
        )
