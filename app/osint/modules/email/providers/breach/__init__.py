"""
TraceLens Breach Provider Package
==================================

Exports all breach provider implementations and the shared
data models / interface from a single import path.

Usage::

    from app.osint.modules.email.providers.breach import (
        BaseBreachProvider,
        BreachRecord,
        ProviderResult,
        HIBPProvider,
        LeakCheckProvider,
        HudsonRockProvider,
    )
"""

from app.osint.modules.email.providers.breach.base import (
    BaseBreachProvider,
    BreachRecord,
    ProviderResult,
)
from app.osint.modules.email.providers.breach.hibp import HIBPProvider
from app.osint.modules.email.providers.breach.leakcheck import LeakCheckProvider
from app.osint.modules.email.providers.breach.hudsonrock import HudsonRockProvider

__all__ = [
    "BaseBreachProvider",
    "BreachRecord",
    "ProviderResult",
    "HIBPProvider",
    "LeakCheckProvider",
    "HudsonRockProvider",
]
