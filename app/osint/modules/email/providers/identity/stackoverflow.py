"""
============================================================
TraceLens Stack Overflow Identity Provider
============================================================

Identity provider implementation for Stack Overflow.
Returns status 'unsupported' as Stack Overflow API / public web interface does not permit direct email-based identity discovery for privacy protection.

Author:
    TraceLens
"""

import logging
import time

from app.osint.modules.email.providers.identity.base import (
    BaseIdentityProvider,
    IdentityProviderResult,
)

logger = logging.getLogger(__name__)


class StackOverflowIdentityProvider(BaseIdentityProvider):
    """
    Stack Overflow Identity Discovery Provider.
    """

    provider_name = "Stack Overflow"

    def search(self, email: str) -> IdentityProviderResult:
        """
        Returns unsupported status in compliance with Stack Overflow privacy policies.
        """
        start_time = time.perf_counter()
        normalized_email = self.normalize_email(email)

        logger.info(
            "[%s] Identity lookup queried for '%s' -> Returning unsupported (Privacy Policy)",
            self.provider_name,
            normalized_email,
        )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return IdentityProviderResult(
            provider=self.provider_name,
            found=False,
            available=True,
            status="unsupported",
            reason="Public email lookup is not available due to platform privacy protections.",
            metadata={"execution_time_ms": elapsed_ms},
        )
