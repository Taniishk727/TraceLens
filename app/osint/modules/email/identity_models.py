"""
============================================================
TraceLens Email Identity Intelligence Data Models
============================================================

Dataclasses and standardized data structures for Email Identity Intelligence,
evidence extraction, username discovery, handoff preparation, unified avatars,
and identity confidence rationale.

Author:
    TraceLens
"""

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class DiscoveredUsername:
    """
    Represents a real public username discovered from an identity provider.
    Note: Do NOT generate handles from the target email.
    """
    provider: str
    username: str

    def to_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "username": self.username,
        }


@dataclass
class UsernameCandidate:
    """
    Prepared handoff object for future correlation with the Username module.
    """
    provider: str
    username: str
    confidence: str = "High"

    def to_dict(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "username": self.username,
            "confidence": self.confidence,
        }


@dataclass
class EvidenceItem:
    """
    Represents a discrete piece of identity evidence discovered during email OSINT.
    """
    type: str  # e.g., "Public Avatar", "Public Display Name", "Public Username", etc.
    value: str
    provider: str
    confidence: str = "HIGH"

    def to_dict(self) -> dict[str, str]:
        return {
            "type": self.type,
            "value": self.value,
            "provider": self.provider,
            "confidence": self.confidence,
        }


@dataclass
class UnifiedAvatarCard:
    """
    Represents a merged or single public avatar card.
    Identical avatars across providers (e.g., Gravatar and Libravatar) are merged.
    """
    avatar_url: str
    display_name: str | None = None
    primary_username: str | None = None
    location: str | None = None
    website: str | None = None
    providers: list[str] = field(default_factory=list)
    profile_urls: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "avatar_url": self.avatar_url,
            "display_name": self.display_name,
            "primary_username": self.primary_username,
            "location": self.location,
            "website": self.website,
            "providers": self.providers,
            "profile_urls": self.profile_urls,
        }


@dataclass
class IdentitySummary:
    """
    High-level summary of all successful identity discoveries with confidence rationale.
    """
    profiles_found: int = 0
    primary_identity: dict[str, Any] | None = None
    evidence_count: int = 0
    confidence: str = "LOW"
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profiles_found": self.profiles_found,
            "primary_identity": self.primary_identity,
            "evidence_count": self.evidence_count,
            "confidence": self.confidence,
            "reasons": self.reasons,
        }


@dataclass
class TimelineStep:
    """
    Single step in the Identity Discovery Timeline.
    """
    step: str
    label: str
    description: str

    def to_dict(self) -> dict[str, str]:
        return {
            "step": self.step,
            "label": self.label,
            "description": self.description,
        }
