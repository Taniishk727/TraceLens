"""
============================================================
TraceLens Email OSINT Module
============================================================

Provides modular, extensible email investigation and parsing capabilities.
"""

from app.osint.modules.email.validator import (
    EmailValidator,
    EmailValidationResult,
    InvalidEmailError,
)
from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.collectors import (
    DomainCollector,
    VerificationCollector,
    ProviderCollector,
    GravatarCollector,
    AvatarCollector,
    IdentityCollector,
    AccountPresenceCollector,
    PGPCollector,
    GitCollector,
    BreachCollector,
    PublicSearchCollector,
    ReputationCollector,
)
from app.osint.modules.email.engine import (
    EmailEngine,
    investigate,
)

__all__ = [
    "EmailValidator",
    "EmailValidationResult",
    "InvalidEmailError",
    "BaseCollector",
    "EmailEngine",
    "DomainCollector",
    "VerificationCollector",
    "ProviderCollector",
    "GravatarCollector",
    "AvatarCollector",
    "IdentityCollector",
    "AccountPresenceCollector",
    "PGPCollector",
    "GitCollector",
    "BreachCollector",
    "PublicSearchCollector",
    "ReputationCollector",
    "investigate",
]
