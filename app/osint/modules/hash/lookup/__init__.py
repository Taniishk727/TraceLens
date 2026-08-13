"""
============================================================
TraceLens Hash Lookup Module
============================================================

Public hash lookup and plaintext recovery engine abstraction for TraceLens.

Author:
    TraceLens
"""

from app.osint.modules.hash.lookup.base import BaseLookupSource
from app.osint.modules.hash.lookup.models import (
    LookupResult,
    LookupSourceCapability,
    LookupStatus,
)
from app.osint.modules.hash.lookup.registry import LookupRegistry, execute_lookup

__all__ = [
    "BaseLookupSource",
    "LookupResult",
    "LookupSourceCapability",
    "LookupStatus",
    "LookupRegistry",
    "execute_lookup",
]
