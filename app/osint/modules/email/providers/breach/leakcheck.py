"""
============================================================
TraceLens LeakCheck Breach Provider — Stub
============================================================

Scaffold for the LeakCheck breach intelligence provider.

Status: NOT YET IMPLEMENTED

To implement:
    1. Obtain a LeakCheck API key from https://leakcheck.io/
    2. Set the ``LEAKCHECK_API_KEY`` environment variable.
    3. Implement the ``search`` method following the pattern
       established by ``HIBPProvider``.
    4. Register the provider in ``BreachCollector.__init__``.

Author:
    TraceLens
"""

import logging

from app.osint.modules.email.providers.breach.base import (
    BaseBreachProvider,
    ProviderResult,
)

logger = logging.getLogger(__name__)

LEAKCHECK_API_KEY_ENV = "LEAKCHECK_API_KEY"


class LeakCheckProvider(BaseBreachProvider):
    """
    LeakCheck breach intelligence provider (stub — not yet implemented).

    Returns ``available=False`` until the provider is fully implemented.
    Add ``LeakCheckProvider()`` to the ``BreachCollector`` provider list
    after implementation.
    """

    provider_name: str = "LeakCheck"

    def __init__(self, timeout: float = 6.0) -> None:
        self.timeout = timeout

    def search(self, email: str) -> ProviderResult:
        """
        Stub implementation — returns unavailable until implemented.

        Args:
            email: Email address to search.

        Returns:
            ``ProviderResult(available=False)`` always.
        """
        logger.debug(
            "[LeakCheck] Provider stub invoked for %s — not yet implemented.", email
        )
        return ProviderResult(
            provider_name=self.provider_name,
            available=False,
            error_message="LeakCheck provider is not yet implemented.",
        )
