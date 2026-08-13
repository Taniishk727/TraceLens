"""
============================================================
TraceLens Hash Lookup - Base Abstract Class
============================================================

Defines the abstract interface for all public hash lookup sources.

Author:
    TraceLens
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from app.osint.modules.hash.lookup.models import LookupResult, LookupSourceCapability


class BaseLookupSource(ABC):
    """
    Abstract base class for public hash lookup integration sources.
    """

    def __init__(self, timeout: float = 6.0):
        self.timeout = timeout

    @property
    @abstractmethod
    def capability(self) -> LookupSourceCapability:
        """Returns the capability metadata for this lookup source."""
        pass

    @abstractmethod
    def lookup(
        self, hash_value: str, possible_algorithms: Optional[List[str]] = None
    ) -> LookupResult:
        """
        Queries the public lookup source for an exact plaintext match.

        Args:
            hash_value: Normalized hash string to query.
            possible_algorithms: Optional list of candidate algorithms identified in Feature 1.

        Returns:
            LookupResult detailing match status, recovered plaintext, and source metadata.
        """
        pass
