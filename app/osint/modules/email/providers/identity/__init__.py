"""
============================================================
TraceLens Email Module - Identity Providers Package
============================================================

Contains public identity providers (Gravatar, Libravatar, GitHub, GitLab, Stack Overflow).

Author:
    TraceLens
"""

from app.osint.modules.email.providers.identity.base import (
    BaseIdentityProvider,
    IdentityProviderResult,
)
from app.osint.modules.email.providers.identity.gravatar import GravatarIdentityProvider
from app.osint.modules.email.providers.identity.libravatar import LibravatarIdentityProvider
from app.osint.modules.email.providers.identity.github import GitHubIdentityProvider
from app.osint.modules.email.providers.identity.gitlab import GitLabIdentityProvider
from app.osint.modules.email.providers.identity.stackoverflow import StackOverflowIdentityProvider

__all__ = [
    "BaseIdentityProvider",
    "IdentityProviderResult",
    "GravatarIdentityProvider",
    "LibravatarIdentityProvider",
    "GitHubIdentityProvider",
    "GitLabIdentityProvider",
    "StackOverflowIdentityProvider",
]
