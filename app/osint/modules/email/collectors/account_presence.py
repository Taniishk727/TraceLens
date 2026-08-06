"""
============================================================
TraceLens Email Account Presence Collector
============================================================

Orchestrates account presence providers (GitHub, GitLab, Gravatar, Libravatar,
Reddit, Discord, Adobe, Spotify, Canva, Docker Hub) concurrently to determine
email registration status across online platforms.

Author:
    TraceLens
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time
from typing import Any

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import EmailValidationResult
from app.osint.modules.email.providers.presence import (
    BasePresenceProvider,
    AccountPresenceResult,
    GravatarPresenceProvider,
    LibravatarPresenceProvider,
    GitHubPresenceProvider,
    GitLabPresenceProvider,
    RedditPresenceProvider,
    DiscordPresenceProvider,
    AdobePresenceProvider,
    SpotifyPresenceProvider,
    CanvaPresenceProvider,
    DockerPresenceProvider,
)

logger = logging.getLogger(__name__)


class AccountPresenceCollector(BaseCollector):
    """
    Account Presence Collector.

    Executes all configured presence providers concurrently, aggregating account
    registration metrics across online platforms.
    """

    def __init__(self, providers: list[BasePresenceProvider] | None = None):
        super().__init__(name="Account Presence Collector", category="Account")
        if providers is None:
            self.providers: list[BasePresenceProvider] = [
                GitHubPresenceProvider(),
                GitLabPresenceProvider(),
                GravatarPresenceProvider(),
                LibravatarPresenceProvider(),
                RedditPresenceProvider(),
                DiscordPresenceProvider(),
                AdobePresenceProvider(),
                SpotifyPresenceProvider(),
                CanvaPresenceProvider(),
                DockerPresenceProvider(),
            ]
        else:
            self.providers = providers

    def _execute_provider_safe(
        self, provider: BasePresenceProvider, email: str
    ) -> AccountPresenceResult:
        """Safely invokes a single provider check with timing and exception isolation."""
        t0 = time.perf_counter()
        try:
            res = provider.check(email)
            return res
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            logger.error(
                "[AccountPresenceCollector] Provider %s crashed: %s",
                provider.provider_name,
                exc,
                exc_info=True,
            )
            return AccountPresenceResult(
                provider=provider.provider_name,
                status="ERROR",
                confidence="LOW",
                profile_public=False,
                notes=f"Provider runtime error: {str(exc)}",
                metadata={"execution_time_ms": elapsed_ms},
            )

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes account presence checks across all providers.

        Args:
            validation: Validated target email dataclass.

        Returns:
            Dictionary containing aggregated account presence assessment report.
        """
        normalized_email = validation.email.strip().lower()
        logger.info(
            "[AccountPresenceCollector] Starting account presence check for '%s' across %d provider(s)",
            normalized_email,
            len(self.providers),
        )

        provider_results: list[AccountPresenceResult] = []

        if self.providers:
            workers = min(8, len(self.providers))
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

        registered_count = sum(1 for r in provider_results if r.status == "REGISTERED")
        unknown_count = sum(1 for r in provider_results if r.status == "UNKNOWN")
        unsupported_count = sum(1 for r in provider_results if r.status == "UNSUPPORTED")

        results_dicts = [p.to_dict() for p in provider_results]

        logger.info(
            "[AccountPresenceCollector] Completed check for '%s'. Checked: %d, Registered: %d",
            normalized_email,
            len(provider_results),
            registered_count,
        )

        return {
            "collector": "Account Presence",
            "status": "completed",
            "providers_checked": len(provider_results),
            "registered_accounts": registered_count,
            "unknown_providers": unknown_count,
            "unsupported_providers": unsupported_count,
            "results": results_dicts,
        }
