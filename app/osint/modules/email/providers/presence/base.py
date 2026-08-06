"""
============================================================
TraceLens Account Presence Provider Interface
============================================================

Abstract base class and standardized data models for account presence providers.

Defines:
    - AccountPresenceResult: Standardized response returned by presence providers.
    - BasePresenceProvider: Abstract base class implemented by service providers.

Author:
    TraceLens
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import logging
from typing import Any, Literal

logger = logging.getLogger(__name__)

PresenceStatus = Literal["REGISTERED", "NOT_REGISTERED", "UNKNOWN", "UNSUPPORTED", "ERROR"]
ConfidenceLevel = Literal["HIGH", "MEDIUM", "LOW", "N/A"]


@dataclass
class AccountPresenceResult:
    """
    Standardized result payload returned by an account presence provider.

    Attributes:
        provider: Canonical provider name (e.g. 'GitHub', 'Gravatar').
        status: Registration status ('REGISTERED', 'NOT_REGISTERED', 'UNKNOWN', 'UNSUPPORTED', 'ERROR').
        confidence: Confidence rating in the status assessment ('HIGH', 'MEDIUM', 'LOW', 'N/A').
        profile_public: True if a public user profile exists and is visible.
        profile_url: Public profile URL (e.g., https://github.com/octocat). Never internal API URLs.
        avatar_url: Direct URL to the public avatar image, if available.
        display_name: Public display name or full name of the account holder.
        username: Handle or username on the platform.
        bio: User bio or profile description.
        website: External personal website or blog URL listed on profile.
        location: Geographic location listed on profile.
        notes: Contextual notes or status explanation.
        metadata: Provider-specific metadata (HTTP status codes, API limits, etc.).
    """

    provider: str
    status: PresenceStatus = "UNKNOWN"
    confidence: ConfidenceLevel = "MEDIUM"
    profile_public: bool = False
    profile_url: str | None = None
    avatar_url: str | None = None
    display_name: str | None = None
    username: str | None = None
    bio: str | None = None
    website: str | None = None
    location: str | None = None
    notes: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Returns result as a plain dictionary matching system standards."""
        return {
            "provider": self.provider,
            "status": self.status,
            "confidence": self.confidence,
            "profile_public": self.profile_public,
            "profile_url": self.profile_url,
            "avatar_url": self.avatar_url,
            "display_name": self.display_name,
            "username": self.username,
            "bio": self.bio,
            "website": self.website,
            "location": self.location,
            "notes": self.notes,
            "metadata": self.metadata,
        }


class BasePresenceProvider(ABC):
    """
    Abstract Base Class for all Account Presence Providers.

    Every concrete provider must implement the `check` method.
    """

    #: Human-readable provider identifier.
    provider_name: str = "Unknown"

    @abstractmethod
    def check(self, email: str) -> AccountPresenceResult:
        """
        Checks whether an email address appears to be registered on the service.

        Args:
            email: Stripped and lowercased email address string.

        Returns:
            AccountPresenceResult containing standardized presence assessment.

        Notes:
            Must handle network errors internally without raising exceptions.
        """
        ...

    def normalize_email(self, email: str) -> str:
        """Utility method to ensure target email is stripped and lowercased."""
        if not email:
            return ""
        return email.strip().lower()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} provider='{self.provider_name}'>"
