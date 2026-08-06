"""
============================================================
TraceLens Email Identity Discovery Collector
============================================================

Orchestrates public identity discovery providers (GitHub, GitLab, Stack Overflow,
Gravatar, Libravatar) concurrently to build a unified identity profile report.

Author:
    TraceLens
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time
from typing import Any

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import EmailValidationResult
from app.osint.modules.email.providers.identity import (
    BaseIdentityProvider,
    IdentityProviderResult,
    GitHubIdentityProvider,
    GitLabIdentityProvider,
    StackOverflowIdentityProvider,
    GravatarIdentityProvider,
    LibravatarIdentityProvider,
)

logger = logging.getLogger(__name__)

# Profile Priority Order as specified
PRIORITY_ORDER = {
    "GitHub": 1,
    "GitLab": 2,
    "Stack Overflow": 3,
    "Gravatar": 4,
    "Libravatar": 5,
}


class IdentityCollector(BaseCollector):
    """
    Email Identity Discovery Collector.

    Queries all configured public identity providers concurrently, extracts profiles and avatars,
    and merges findings according to platform priority.
    """

    def __init__(self, providers: list[BaseIdentityProvider] | None = None):
        super().__init__(name="Identity Discovery Collector", category="Identity")
        if providers is None:
            self.providers: list[BaseIdentityProvider] = [
                GitHubIdentityProvider(),
                GitLabIdentityProvider(),
                StackOverflowIdentityProvider(),
                GravatarIdentityProvider(),
                LibravatarIdentityProvider(),
            ]
        else:
            self.providers = providers

    def _execute_provider_safe(
        self, provider: BaseIdentityProvider, email: str
    ) -> IdentityProviderResult:
        """Safely invokes a single provider search with timing and exception handling."""
        t0 = time.perf_counter()
        try:
            res = provider.search(email)
            return res
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            logger.error(
                "[IdentityCollector] Provider %s crashed: %s",
                provider.provider_name,
                exc,
                exc_info=True,
            )
            return IdentityProviderResult(
                provider=provider.provider_name,
                found=False,
                available=False,
                status="failed",
                reason=f"Provider runtime error: {str(exc)}",
                metadata={"execution_time_ms": elapsed_ms},
            )

    def _select_primary_profile(
        self, provider_results: list[IdentityProviderResult]
    ) -> tuple[dict[str, Any] | None, str | None]:
        """
        Selects the primary profile and primary avatar according to platform priority:
        GitHub -> GitLab -> Stack Overflow -> Gravatar -> Libravatar
        """
        found_results = [r for r in provider_results if r.found]
        if not found_results:
            return None, None

        # Sort found profiles by PRIORITY_ORDER
        sorted_found = sorted(
            found_results,
            key=lambda r: PRIORITY_ORDER.get(r.provider, 99),
        )

        primary_res = sorted_found[0]
        primary_profile = primary_res.to_dict()

        # Primary avatar selection: try primary profile avatar first, or fallback to any found avatar
        primary_avatar = primary_res.avatar_url
        if not primary_avatar:
            for r in sorted_found:
                if r.avatar_url:
                    primary_avatar = r.avatar_url
                    break

        return primary_profile, primary_avatar

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes identity discovery across all providers.

        Args:
            validation: Validated target email dataclass.

        Returns:
            Dictionary containing unified identity report.
        """
        normalized_email = validation.email.strip().lower()
        logger.info(
            "[IdentityCollector] Starting identity discovery for '%s' across %d provider(s)",
            normalized_email,
            len(self.providers),
        )

        provider_results: list[IdentityProviderResult] = []

        if self.providers:
            workers = min(5, len(self.providers))
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

        # Preserve provider configuration order
        provider_name_order = {p.provider_name: i for i, p in enumerate(self.providers)}
        provider_results.sort(
            key=lambda r: provider_name_order.get(r.provider, 999)
        )

        profiles_found_count = sum(1 for r in provider_results if r.found)
        primary_profile, primary_avatar = self._select_primary_profile(provider_results)

        profiles_dicts = [p.to_dict() for p in provider_results]

        logger.info(
            "[IdentityCollector] Completed identity discovery for '%s'. Checked: %d, Profiles Found: %d",
            normalized_email,
            len(provider_results),
            profiles_found_count,
        )

        return {
            "collector": "Identity Discovery",
            "status": "completed" if profiles_found_count > 0 else "not_found",
            "profiles_found": profiles_found_count,
            "providers_checked": len(provider_results),
            "primary_profile": primary_profile,
            "primary_avatar": primary_avatar,
            "profiles": profiles_dicts,
        }
