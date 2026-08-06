"""
============================================================
TraceLens Hudson Rock Breach Provider — Stub
============================================================

Scaffold for the Hudson Rock (Cavalier) breach intelligence provider.

Status: NOT YET IMPLEMENTED

To implement:
    1. Obtain a Hudson Rock API key from https://hudsonrock.com/
    2. Set the ``HUDSONROCK_API_KEY`` environment variable.
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

HUDSONROCK_API_KEY_ENV = "HUDSONROCK_API_KEY"


class HudsonRockProvider(BaseBreachProvider):
    """
    Hudson Rock (Cavalier) breach intelligence provider (stub — not yet implemented).

    Returns ``available=False`` until the provider is fully implemented.
    Add ``HudsonRockProvider()`` to the ``BreachCollector`` provider list
    after implementation.
    """

    provider_name: str = "HudsonRock"

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
            "[HudsonRock] Provider stub invoked for %s — not yet implemented.", email
        )
        return ProviderResult(
            provider_name=self.provider_name,
            available=False,
            error_message="Hudson Rock provider is not yet implemented.",
        )
