"""
============================================================
TraceLens Breach Provider Abstraction Layer
============================================================

Base classes and data models for breach intelligence providers.

Defines:
    - BreachRecord: Normalized per-breach data record.
    - ProviderResult: Aggregate result returned by any breach provider.
    - BaseBreachProvider: Abstract interface all providers must implement.

Author:
    TraceLens
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


# ==========================================================
# DATA MODELS
# ==========================================================


@dataclass
class BreachRecord:
    """
    Normalized data record representing a single breach event.

    All provider-specific field names are mapped to this common
    structure so the collector and UI never need to know which
    provider produced the data.
    """

    name: str
    """Human-readable breach name (e.g. 'Adobe', 'LinkedIn')."""

    domain: str
    """Root domain of the breached service (e.g. 'adobe.com')."""

    breach_date: str
    """ISO-8601 date the breach occurred (e.g. '2013-10-04')."""

    added_date: str
    """ISO-8601 date the breach was added to the database."""

    description: str
    """Plain-text summary of the breach event."""

    data_classes: list[str] = field(default_factory=list)
    """List of data category strings exposed (e.g. ['Email addresses', 'Passwords'])."""

    verified: bool = True
    """Whether the breach has been independently verified."""

    sensitive: bool = False
    """Whether the breach is flagged as sensitive / adult content."""

    retired: bool = False
    """Whether the breach has been marked retired / superseded."""

    spam_list: bool = False
    """Whether this entry is a spam list rather than a genuine breach."""

    def to_dict(self) -> dict[str, Any]:
        """Returns breach record as a plain dictionary."""
        return {
            "name": self.name,
            "domain": self.domain,
            "breach_date": self.breach_date,
            "added_date": self.added_date,
            "description": self.description,
            "data_classes": self.data_classes,
            "verified": self.verified,
            "sensitive": self.sensitive,
            "retired": self.retired,
            "spam_list": self.spam_list,
        }


@dataclass
class ProviderResult:
    """
    Aggregate result returned by a breach provider after querying an email.

    Contains both metadata about the provider's availability and the
    normalized list of breach records discovered.
    """

    provider_name: str
    """Canonical name of the provider (e.g. 'HIBP')."""

    available: bool
    """True if the provider is reachable and configured (API key present, etc.)."""

    email_found: bool = False
    """True if the email address was found in at least one breach."""

    total_breaches: int = 0
    """Total number of distinct breaches discovered for this email."""

    total_data_categories: int = 0
    """Total distinct data category labels across all breaches."""

    breaches: list[BreachRecord] = field(default_factory=list)
    """Normalized list of breach records."""

    error_message: str | None = None
    """Human-readable error or unavailability reason, if applicable."""

    def to_dict(self) -> dict[str, Any]:
        """Returns the full provider result as a plain dictionary."""
        return {
            "provider_name": self.provider_name,
            "available": self.available,
            "email_found": self.email_found,
            "total_breaches": self.total_breaches,
            "total_data_categories": self.total_data_categories,
            "breaches": [b.to_dict() for b in self.breaches],
            "error_message": self.error_message,
        }


# ==========================================================
# PROVIDER INTERFACE
# ==========================================================


class BaseBreachProvider(ABC):
    """
    Abstract base class for all breach intelligence providers.

    Each concrete provider (HIBP, LeakCheck, HudsonRock, …) must
    implement the ``search`` method and return a ``ProviderResult``.

    This interface ensures the ``BreachCollector`` can swap, combine,
    or extend providers without any changes to the collector or engine.
    """

    #: Canonical human-readable provider name.
    provider_name: str = "Unknown"

    @abstractmethod
    def search(self, email: str) -> ProviderResult:
        """
        Query the provider for breach records associated with the given email.

        Args:
            email: Normalized (lowercase, stripped) email address to search.

        Returns:
            ProviderResult with normalized breach records and availability status.

        Notes:
            Implementations must NEVER raise exceptions — all errors must be
            caught and expressed as ``ProviderResult(available=False, error_message=...)``.
        """
        ...

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} provider='{self.provider_name}'>"
