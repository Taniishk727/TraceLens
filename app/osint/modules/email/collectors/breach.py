"""
============================================================
TraceLens Data Breach OSINT Collector
============================================================

Orchestrates breach intelligence queries by delegating to one or
more registered ``BaseBreachProvider`` implementations.

Architecture
------------
The collector acts as a thin coordinator:

    EmailEngine
        │
        ▼
    BreachCollector.collect()
        │   (iterates providers in priority order)
        ├─► HIBPProvider.search(email)      → ProviderResult
        ├─► LeakCheckProvider.search(email) → ProviderResult  (future)
        └─► HudsonRockProvider.search(email)→ ProviderResult  (future)

Only the first *available* provider result is used in the current
implementation.  Extending to aggregate multiple providers requires
no changes to the engine or template.

Configuration
-------------
HIBP_API_KEY
    HaveIBeenPwned API v3 key.
    Obtain at: https://haveibeenpwned.com/API/Key
    If absent, the provider is marked unavailable and the collector
    returns ``status="unavailable"`` with a human-readable message.

Return Format
-------------
The ``collect()`` method returns a dict containing:

    collector          str   — "Breach Collector"
    status             str   — "completed" | "not_found" | "unavailable"
    provider           str   — "HIBP" (or whichever provider responded)
    provider_available bool  — whether the provider could be reached
    email_found        bool  — whether the email appeared in any breach
    total_breaches     int   — number of distinct breaches found
    total_data_categories int — distinct exposed data category count
    breaches           list  — list of normalized breach record dicts
    reason             str   — human-readable summary sentence

    # Backward-compatible legacy fields (kept for existing tests/templates):
    pwned_status       bool | None
    breaches_found     int
    breach_sources     list[str]

Author:
    TraceLens
"""

import logging
import os
import time
from typing import Any

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import EmailValidationResult
from app.osint.modules.email.providers.breach import (
    BaseBreachProvider,
    ProviderResult,
    HIBPProvider,
    LeakCheckProvider,
    HudsonRockProvider,
)

logger = logging.getLogger(__name__)


class BreachCollector(BaseCollector):
    """
    Threat Intelligence & Data Breach Collector.

    Delegates breach lookups to a prioritised list of
    ``BaseBreachProvider`` instances.  The collector selects the
    first provider that reports itself as available and returns
    its normalized ``ProviderResult``.

    Attributes:
        providers: Ordered list of breach provider instances.
        timeout: Default HTTP timeout forwarded to provider constructors.
        hibp_api_key: Exposed for unit-test patching (mirrors legacy interface).
    """

    def __init__(self, timeout: float = 6.0) -> None:
        super().__init__(name="Breach Collector", category="Threat Intelligence")
        self.timeout = timeout

        # ----------------------------------------------------------------
        # Legacy attribute — kept for backward-compatibility with existing
        # test code that patches `collector.hibp_api_key` directly.
        # ----------------------------------------------------------------
        self.hibp_api_key: str | None = os.getenv("HIBP_API_KEY")

        # ----------------------------------------------------------------
        # Registered providers in priority order.
        # LeakCheck and HudsonRock are registered as stubs so they can be
        # activated simply by implementing their search() methods.
        # ----------------------------------------------------------------
        self.providers: list[BaseBreachProvider] = [
            HIBPProvider(timeout=self.timeout),
            LeakCheckProvider(timeout=self.timeout),
            HudsonRockProvider(timeout=self.timeout),
        ]

    # ------------------------------------------------------------------
    # Legacy compatibility method
    # ------------------------------------------------------------------

    def query_hibp(self, email: str) -> dict[str, Any] | None:
        """
        HIBP query method — patchable for backward compatibility.

        Existing tests that mock this method to return a legacy dict
        (``{"pwned": ..., "breaches_found": ..., "breach_sources": [...]}``) will
        continue to work unmodified.  For real (non-mocked) calls the method
        also embeds the full ``ProviderResult`` under the private
        ``_provider_result`` key so ``collect()`` can build rich breach data.

        Returns:
            Dict with legacy keys ``pwned``, ``breaches_found``, ``breach_sources``
            plus ``_provider_result`` (ProviderResult), or ``None`` on
            network failure / key not configured.
        """
        provider = HIBPProvider(timeout=self.timeout, api_key=self.hibp_api_key)
        result = provider.search(email)

        if not result.available:
            return None

        return {
            "pwned": result.email_found,
            "breaches_found": result.total_breaches,
            "breach_sources": [b.name for b in result.breaches],
            # Internal key — present only in real calls, not when mocked by tests.
            "_provider_result": result,
        }

    # ------------------------------------------------------------------
    # Main collector entry-point
    # ------------------------------------------------------------------

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Execute breach intelligence collection for the validated email.

        Iterates registered providers in priority order and uses the
        first available result.

        Args:
            validation: Parsed and validated email metadata.

        Returns:
            Standardized collector result dictionary.
        """
        email = validation.email
        t0 = time.perf_counter()
        logger.info("[Breach] Starting breach intelligence collection for %s", email)

        # ----------------------------------------------------------------
        # HIBP path — call self.query_hibp() so tests can patch it.
        # ----------------------------------------------------------------
        provider_result: ProviderResult | None = None
        provider_name: str = "None"
        _legacy_sources: list[str] = []  # Populated only in the mocked-path branch.

        if self.hibp_api_key:
            logger.debug("[Breach] Trying provider: HIBP")
            hibp_raw = self.query_hibp(email)

            if hibp_raw is not None:
                # Real call: _provider_result carries full BreachRecord objects.
                # Mocked call: key absent — fall back to legacy dict fields.
                embedded: ProviderResult | None = hibp_raw.get("_provider_result")
                if embedded is not None:
                    provider_result = embedded
                    provider_name = embedded.provider_name
                    logger.info(
                        "[Breach] HIBP responded (available). Using rich result."
                    )
                else:
                    # Mocked — reconstruct a minimal ProviderResult from legacy keys.
                    provider_name = "HIBP"
                    pwned: bool = bool(hibp_raw.get("pwned", False))
                    sources: list[str] = hibp_raw.get("breach_sources", [])
                    _legacy_sources = sources  # Preserve for final assembly.
                    provider_result = ProviderResult(
                        provider_name=provider_name,
                        available=True,
                        email_found=pwned,
                        total_breaches=hibp_raw.get("breaches_found", len(sources)),
                        total_data_categories=0,
                        breaches=[],  # No rich BreachRecord objects in mocked call.
                    )
                    logger.info(
                        "[Breach] HIBP responded via legacy shim (mocked path)."
                    )
            # hibp_raw is None → HIBP provider unavailable (key invalid / network error)

        # ----------------------------------------------------------------
        # Fallback: try non-HIBP providers (LeakCheck, HudsonRock, …)
        # ----------------------------------------------------------------
        if provider_result is None:
            for provider in self.providers[1:]:
                logger.debug("[Breach] Trying provider: %s", provider.provider_name)
                result = provider.search(email)
                if result.available:
                    logger.info(
                        "[Breach] Provider %s responded. Using this result.",
                        provider.provider_name,
                    )
                    provider_result = result
                    provider_name = result.provider_name
                    break
                else:
                    logger.debug(
                        "[Breach] Provider %s unavailable: %s",
                        provider.provider_name,
                        result.error_message,
                    )

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        # ----------------------------------------------------------------
        # No available provider found
        # ----------------------------------------------------------------
        if provider_result is None:
            logger.info(
                "[Breach] No available breach provider for %s. "
                "Configure at least one provider API key.",
                email,
            )
            return {
                "collector": self.name,
                "status": "unavailable",
                "provider": provider_name,
                "provider_available": False,
                "email_found": False,
                "total_breaches": 0,
                "total_data_categories": 0,
                "breaches": [],
                # Legacy fields
                "pwned_status": None,
                "breaches_found": 0,
                "breach_sources": [],
                "reason": (
                    "No breach provider API key configured "
                    "(HIBP_API_KEY required)."
                ),
            }

        # ----------------------------------------------------------------
        # Build breach sources list for legacy compatibility.
        # For real calls: derive from BreachRecord objects.
        # For mocked calls: fall back to the raw list captured earlier.
        breach_sources: list[str] = (
            [b.name for b in provider_result.breaches]
            if provider_result.breaches
            else _legacy_sources
        )
        breach_dicts: list[dict[str, Any]] = [
            b.to_dict() for b in provider_result.breaches
        ]

        # ----------------------------------------------------------------
        # Compose final collector result
        # ----------------------------------------------------------------
        if provider_result.email_found:
            status = "completed"
            reason = (
                f"Discovered in {provider_result.total_breaches} data breach(es) "
                f"via {provider_result.provider_name}. "
                f"{provider_result.total_data_categories} distinct data categories exposed."
            )
            logger.info(
                "[Breach] %s found in %d breach(es) via %s. Elapsed: %.2f ms",
                email,
                provider_result.total_breaches,
                provider_result.provider_name,
                elapsed_ms,
            )
        else:
            status = "not_found"
            reason = (
                f"No breach records found for this email in "
                f"{provider_result.provider_name} database."
            )
            logger.info(
                "[Breach] %s not found in any breach via %s. Elapsed: %.2f ms",
                email,
                provider_result.provider_name,
                elapsed_ms,
            )

        return {
            "collector": self.name,
            "status": status,
            "provider": provider_result.provider_name,
            "provider_available": provider_result.available,
            "email_found": provider_result.email_found,
            "total_breaches": provider_result.total_breaches,
            "total_data_categories": provider_result.total_data_categories,
            "breaches": breach_dicts,
            # Legacy fields — backward-compatible with existing tests/templates
            "pwned_status": provider_result.email_found,
            "breaches_found": provider_result.total_breaches,
            "breach_sources": breach_sources,
            "reason": reason,
        }
