"""
============================================================
TraceLens Public Identity Provider Interface
============================================================

Abstract base class and standardized data models for public identity providers.

Defines:
    - IdentityProviderResult: Standardized result returned by identity providers.
    - BaseIdentityProvider: Abstract base class implemented by platform providers.

Author:
    TraceLens
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import logging
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class IdentityProviderResult:
    """
    Standardized result payload returned by an identity discovery provider.

    Attributes:
        provider: Canonical provider name (e.g. 'GitHub', 'Gravatar').
        found: True if a public user profile associated with the email was found.
        available: True if provider API/check completed without unhandled exception.
        status: Operation status ('completed', 'unsupported', 'not_found', 'failed').
        profile_url: Direct link to the public user profile.
        display_name: Full name or display name of the user.
        username: Handle / username on the platform.
        avatar_url: Direct URL to the user's public avatar image.
        bio: User bio or profile description.
        location: Geographic location listed on profile.
        website: External personal website or blog URL listed on profile.
        reason: Human-readable status explanation or error message.
        metadata: Raw or provider-specific metrics (e.g. HTTP status, API limits).
    """

    provider: str
    found: bool = False
    available: bool = True
    status: str = "completed"
    profile_url: str | None = None
    display_name: str | None = None
    username: str | None = None
    avatar_url: str | None = None
    bio: str | None = None
    location: str | None = None
    website: str | None = None
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Returns result as a plain dictionary matching system standards."""
        return {
            "provider": self.provider,
            "found": self.found,
            "available": self.available,
            "status": self.status,
            "profile_url": self.profile_url,
            "display_name": self.display_name,
            "username": self.username,
            "avatar_url": self.avatar_url,
            "bio": self.bio,
            "location": self.location,
            "website": self.website,
            "reason": self.reason,
            "metadata": self.metadata,
        }


class BaseIdentityProvider(ABC):
    """
    Abstract Base Class for all Identity Discovery Providers.

    Every concrete provider must implement the `search` method.
    """

    #: Human-readable provider identifier.
    provider_name: str = "Unknown"

    @abstractmethod
    def search(self, email: str) -> IdentityProviderResult:
        """
        Queries the platform for a public user profile matching the given email.

        Args:
            email: Stripped and lowercased email address string.

        Returns:
            IdentityProviderResult containing standardized profile data.

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
