"""
============================================================
TraceLens Public Avatar Collector
============================================================

Aggregates public avatar intelligence across multiple avatar providers
(Gravatar, Libravatar) concurrently.

Author:
    TraceLens
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time
from typing import Any

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import EmailValidationResult
from app.osint.modules.email.providers.avatar import (
    BaseAvatarProvider,
    AvatarProviderResult,
    GravatarProvider,
    LibravatarProvider,
)

logger = logging.getLogger(__name__)


class AvatarCollector(BaseCollector):
    """
    Public Avatar Collector.

    Executes all configured public avatar providers concurrently and aggregates
    results into a single unified report.
    """

    def __init__(self, providers: list[BaseAvatarProvider] | None = None):
        super().__init__(name="Public Avatar Collector", category="Avatar")
        if providers is None:
            self.providers: list[BaseAvatarProvider] = [
                GravatarProvider(),
                LibravatarProvider(),
            ]
        else:
            self.providers = providers

    def _execute_provider_safe(
        self, provider: BaseAvatarProvider, email: str
    ) -> AvatarProviderResult:
        """Safely invokes a single provider search with timing and error isolation."""
        t0 = time.perf_counter()
        try:
            res = provider.search(email)
            return res
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            logger.error(
                "[AvatarCollector] Provider %s crashed: %s",
                provider.provider_name,
                exc,
                exc_info=True,
            )
            return AvatarProviderResult(
                provider=provider.provider_name,
                available=False,
                found=False,
                metadata={"execution_time_ms": elapsed_ms},
                error_message=f"Provider runtime error: {str(exc)}",
            )

    def _select_best_avatar(
        self, provider_results: list[AvatarProviderResult]
    ) -> dict[str, Any] | None:
        """
        Selects the highest-quality avatar from the list of provider results.

        Quality criteria:
        1. Custom avatar found with display name & profile URL
        2. Custom avatar found with profile URL
        3. Custom avatar found
        """
        found_results = [r for r in provider_results if r.found and r.avatar_url]
        if not found_results:
            return None

        # Sort by quality score
        def quality_score(r: AvatarProviderResult) -> int:
            score = 10
            if r.display_name:
                score += 20
            if r.profile_url:
                score += 10
            if r.provider == "Gravatar":
                score += 5
            return score

        sorted_results = sorted(found_results, key=quality_score, reverse=True)
        best = sorted_results[0]
        return best.to_dict()

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes Public Avatar collection across all providers.

        Args:
            validation: Validated email input dataclass.

        Returns:
            Dictionary containing aggregated public avatar intelligence.
        """
        normalized_email = validation.email.strip().lower()
        logger.info(
            "[AvatarCollector] Starting public avatar collection for '%s' across %d provider(s)",
            normalized_email,
            len(self.providers),
        )

        provider_results: list[AvatarProviderResult] = []

        if self.providers:
            workers = min(4, len(self.providers))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_to_provider = {
                    executor.submit(
                        self._execute_provider_safe, provider, normalized_email
                    ): provider
                    for provider in self.providers
                }
                for future in as_completed(future_to_provider):
                    res = future.result()
                    provider_results.append(res)

        # Preserve order matching self.providers list
        provider_name_order = {p.provider_name: i for i, p in enumerate(self.providers)}
        provider_results.sort(
            key=lambda r: provider_name_order.get(r.provider, 999)
        )

        avatars_found_count = sum(1 for r in provider_results if r.found)
        best_avatar = self._select_best_avatar(provider_results)

        provider_dicts = [p.to_dict() for p in provider_results]

        logger.info(
            "[AvatarCollector] Completed collection for '%s'. Checked: %d, Found: %d",
            normalized_email,
            len(provider_results),
            avatars_found_count,
        )

        return {
            "collector": "Public Avatar",
            "status": "completed" if avatars_found_count > 0 else "not_found",
            "providers_checked": len(provider_results),
            "avatars_found": avatars_found_count,
            "best_avatar": best_avatar,
            "providers": provider_dicts,
        }
