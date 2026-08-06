"""
============================================================
TraceLens Have I Been Pwned (HIBP) Breach Provider
============================================================

Implements the HIBP API v3 breach provider using the
``BaseBreachProvider`` interface.

Configuration:
    Set the ``HIBP_API_KEY`` environment variable with your
    HaveIBeenPwned API key.  Obtain one at:
    https://haveibeenpwned.com/API/Key

    If the key is absent, the provider returns ``available=False``
    immediately without making any network requests.

API Reference:
    https://haveibeenpwned.com/API/v3

Author:
    TraceLens
"""

import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from app.osint.modules.email.providers.breach.base import (
    BaseBreachProvider,
    BreachRecord,
    ProviderResult,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HIBP Constants
# ---------------------------------------------------------------------------

HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_BREACHEDACCOUNT_ENDPOINT = HIBP_BASE_URL + "/breachedaccount/{email}"
HIBP_USER_AGENT = "TraceLens OSINT Engine/1.0 (Security Research)"

#: Env-var name used to read the API key.
HIBP_API_KEY_ENV = "HIBP_API_KEY"


class HIBPProvider(BaseBreachProvider):
    """
    Have I Been Pwned (HIBP) API v3 breach intelligence provider.

    Queries HIBP for all breach records associated with a target email,
    normalizes each breach into a ``BreachRecord``, and returns a
    ``ProviderResult``.

    Gracefully handles:
        - Missing API key (returns unavailable, no network request made)
        - 404 Not Found (email is clean)
        - 401 Unauthorized (bad API key)
        - 429 Rate Limited (backs off gracefully, reports unavailable)
        - 503 Service Unavailable (maintenance mode)
        - Network timeouts
        - Malformed / unexpected JSON
        - Any unexpected exception
    """

    provider_name: str = "HIBP"

    def __init__(self, timeout: float = 6.0, api_key: str | None = None) -> None:
        """
        Initialise the HIBP provider.

        Args:
            timeout: HTTP request timeout in seconds.
            api_key: Optional explicit API key. If omitted, reads from the
                     ``HIBP_API_KEY`` environment variable.
        """
        self.timeout = timeout
        self.api_key: str | None = api_key or os.getenv(HIBP_API_KEY_ENV)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def search(self, email: str) -> ProviderResult:
        """
        Query HIBP for breach data associated with *email*.

        Args:
            email: Normalized email address to search.

        Returns:
            ``ProviderResult`` with full breach details or unavailability status.
        """
        logger.info("[HIBP] Provider selected for breach lookup: %s", email)

        if not self.api_key:
            logger.warning(
                "[HIBP] No API key configured (set %s environment variable).",
                HIBP_API_KEY_ENV,
            )
            return ProviderResult(
                provider_name=self.provider_name,
                available=False,
                error_message=(
                    f"API key not configured. "
                    f"Set the {HIBP_API_KEY_ENV} environment variable."
                ),
            )

        url = HIBP_BREACHEDACCOUNT_ENDPOINT.format(
            email=urllib.parse.quote(email, safe="")
        ) + "?truncateResponse=false"

        logger.info("[HIBP] Sending API request → %s", url)
        t0 = time.perf_counter()

        raw_data = self._fetch(url)

        elapsed = round((time.perf_counter() - t0) * 1000, 1)
        logger.info("[HIBP] Response received in %.1f ms", elapsed)

        # raw_data == None  →  request error (already logged)
        # raw_data == []    →  404 / clean account
        # raw_data == [...]  →  breach records present

        if raw_data is None:
            return ProviderResult(
                provider_name=self.provider_name,
                available=False,
                error_message="Request failed. Check logs for details.",
            )

        if len(raw_data) == 0:
            logger.info("[HIBP] Email %s not found in any breach.", email)
            return ProviderResult(
                provider_name=self.provider_name,
                available=True,
                email_found=False,
                total_breaches=0,
                total_data_categories=0,
                breaches=[],
            )

        breaches = [self._normalise_breach(b) for b in raw_data if isinstance(b, dict)]
        all_categories: set[str] = set()
        for b in breaches:
            all_categories.update(b.data_classes)

        logger.info(
            "[HIBP] Found %d breach(es) for %s covering %d data categories.",
            len(breaches),
            email,
            len(all_categories),
        )

        return ProviderResult(
            provider_name=self.provider_name,
            available=True,
            email_found=True,
            total_breaches=len(breaches),
            total_data_categories=len(all_categories),
            breaches=breaches,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _fetch(self, url: str) -> list[dict[str, Any]] | None:
        """
        Perform the HTTP GET request to the HIBP API.

        Returns:
            Parsed JSON list on success, empty list on 404, None on any error.
        """
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": HIBP_USER_AGENT,
                "hibp-api-key": self.api_key,  # type: ignore[arg-type]
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    body = resp.read().decode("utf-8", errors="ignore")
                    return json.loads(body)
                # Unexpected 2xx with no body — treat as clean
                return []

        except urllib.error.HTTPError as err:
            if err.code == 404:
                # Email not found in any breach — clean result.
                return []
            elif err.code == 401:
                logger.error("[HIBP] 401 Unauthorized — API key is invalid or expired.")
            elif err.code == 429:
                logger.warning(
                    "[HIBP] 429 Rate Limited — too many requests. "
                    "Back off and retry later."
                )
            elif err.code == 503:
                logger.warning("[HIBP] 503 Service Unavailable — HIBP is in maintenance.")
            else:
                logger.warning("[HIBP] HTTP %d error querying %s", err.code, url)
            return None

        except TimeoutError:
            logger.warning("[HIBP] Request timed out after %.1f seconds.", self.timeout)
            return None

        except Exception as exc:
            logger.error("[HIBP] Unexpected error querying HIBP: %s", exc, exc_info=True)
            return None

    @staticmethod
    def _normalise_breach(raw: dict[str, Any]) -> BreachRecord:
        """
        Convert a raw HIBP breach JSON object into a ``BreachRecord``.

        HIBP field mapping:
            Name            → name
            Domain          → domain
            BreachDate      → breach_date
            AddedDate       → added_date  (truncated to date portion)
            Description     → description
            DataClasses     → data_classes
            IsVerified      → verified
            IsSensitive     → sensitive
            IsRetired       → retired
            IsSpamList      → spam_list
        """
        added_raw: str = raw.get("AddedDate", "")
        # AddedDate comes as ISO datetime — keep only the date portion
        added_date = added_raw[:10] if added_raw else ""

        return BreachRecord(
            name=raw.get("Name", "Unknown"),
            domain=raw.get("Domain", ""),
            breach_date=raw.get("BreachDate", ""),
            added_date=added_date,
            description=raw.get("Description", ""),
            data_classes=raw.get("DataClasses", []),
            verified=bool(raw.get("IsVerified", True)),
            sensitive=bool(raw.get("IsSensitive", False)),
            retired=bool(raw.get("IsRetired", False)),
            spam_list=bool(raw.get("IsSpamList", False)),
        )
