"""
============================================================
TraceLens Email Module - Avatar Providers Package
============================================================

Contains public avatar providers (Gravatar, Libravatar).

Author:
    TraceLens
"""

from app.osint.modules.email.providers.avatar.base import (
    BaseAvatarProvider,
    AvatarProviderResult,
)
from app.osint.modules.email.providers.avatar.gravatar import GravatarProvider
from app.osint.modules.email.providers.avatar.libravatar import LibravatarProvider

__all__ = [
    "BaseAvatarProvider",
    "AvatarProviderResult",
    "GravatarProvider",
    "LibravatarProvider",
]
