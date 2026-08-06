"""
============================================================
TraceLens Docker Hub Account Presence Provider
============================================================

Account presence provider for Docker Hub.
Returns status 'UNSUPPORTED' as Docker Hub does not provide an unauthenticated public email account detection API.

Author:
    TraceLens
"""

import logging
import time

from app.osint.modules.email.providers.presence.base import (
    BasePresenceProvider,
    AccountPresenceResult,
)

logger = logging.getLogger(__name__)


class DockerPresenceProvider(BasePresenceProvider):
    """
    Docker Hub Account Presence Provider.
    """

    provider_name = "Docker Hub"

    def check(self, email: str) -> AccountPresenceResult:
        """
        Returns unsupported status in compliance with platform access policies.
        """
        start_time = time.perf_counter()
        normalized_email = self.normalize_email(email)

        logger.info("[%s] Account presence check requested for '%s' -> UNSUPPORTED", self.provider_name, normalized_email)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return AccountPresenceResult(
            provider=self.provider_name,
            status="UNSUPPORTED",
            confidence="N/A",
            profile_public=False,
            notes="Public account detection is unavailable without authentication.",
            metadata={"execution_time_ms": elapsed_ms},
        )
