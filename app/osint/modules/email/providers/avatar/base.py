"""
============================================================
TraceLens Public Avatar Provider Interface
============================================================

Abstract base class and standardized data models for public avatar providers.

Defines:
    - AvatarProviderResult: Standardized response payload from avatar providers.
    - BaseAvatarProvider: Abstract interface implemented by Gravatar, Libravatar, etc.

Author:
    TraceLens
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import logging
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AvatarProviderResult:
    """
    Standardized result returned by any public avatar provider.

    Attributes:
        provider: Canonical provider name (e.g., 'Gravatar', 'Libravatar').
        available: True if the provider check completed without unhandled internal error.
        found: True if a public custom avatar or profile was discovered.
        avatar_url: Direct URL to the avatar image, if found.
        profile_url: Direct URL to the public profile page, if available.
        display_name: Public display name associated with the avatar, if available.
        metadata: Provider-specific metadata (HTTP status codes, hashes, etc.).
        error_message: Human-readable error string if available is False or lookup failed.
    """

    provider: str
    available: bool = True
    found: bool = False
    avatar_url: str | None = None
    profile_url: str | None = None
    display_name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Returns the result as a plain dictionary matching system standards."""
        return {
            "provider": self.provider,
            "available": self.available,
            "found": self.found,
            "avatar_url": self.avatar_url,
            "profile_url": self.profile_url,
            "display_name": self.display_name,
            "metadata": self.metadata,
            "error_message": self.error_message,
        }


class BaseAvatarProvider(ABC):
    """
    Abstract Base Class for all Public Avatar Providers.

    Every concrete avatar provider must implement the `search` method.
    """

    #: Human-readable provider identifier.
    provider_name: str = "Unknown"

    @abstractmethod
    def search(self, email: str) -> AvatarProviderResult:
        """
        Executes avatar discovery for a normalized email address.

        Args:
            email: Stripped and lowercased email address string.

        Returns:
            AvatarProviderResult containing provider metrics and findings.

        Notes:
            Implementations must handle network/HTTP exceptions internally and
            never raise errors to the caller.
        """
        ...

    def normalize_email(self, email: str) -> str:
        """Utility method to ensure target email is stripped and lowercased."""
        if not email:
            return ""
        return email.strip().lower()

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} provider='{self.provider_name}'>"
