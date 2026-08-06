"""
============================================================
TraceLens Email Module - Presence Providers Package
============================================================

Contains account presence providers (Gravatar, Libravatar, GitHub, GitLab,
Reddit, Discord, Adobe, Spotify, Canva, Docker Hub).

Author:
    TraceLens
"""

from app.osint.modules.email.providers.presence.base import (
    BasePresenceProvider,
    AccountPresenceResult,
)
from app.osint.modules.email.providers.presence.gravatar import GravatarPresenceProvider
from app.osint.modules.email.providers.presence.libravatar import LibravatarPresenceProvider
from app.osint.modules.email.providers.presence.github import GitHubPresenceProvider
from app.osint.modules.email.providers.presence.gitlab import GitLabPresenceProvider
from app.osint.modules.email.providers.presence.reddit import RedditPresenceProvider
from app.osint.modules.email.providers.presence.discord import DiscordPresenceProvider
from app.osint.modules.email.providers.presence.adobe import AdobePresenceProvider
from app.osint.modules.email.providers.presence.spotify import SpotifyPresenceProvider
from app.osint.modules.email.providers.presence.canva import CanvaPresenceProvider
from app.osint.modules.email.providers.presence.docker import DockerPresenceProvider

__all__ = [
    "BasePresenceProvider",
    "AccountPresenceResult",
    "GravatarPresenceProvider",
    "LibravatarPresenceProvider",
    "GitHubPresenceProvider",
    "GitLabPresenceProvider",
    "RedditPresenceProvider",
    "DiscordPresenceProvider",
    "AdobePresenceProvider",
    "SpotifyPresenceProvider",
    "CanvaPresenceProvider",
    "DockerPresenceProvider",
]
