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
from app.osint.modules.email.engine import (
    EmailEngine,
    BaseCollector,
    ProviderCollector,
    DomainCollector,
    ReputationCollector,
    GravatarCollector,
    UsernameCorrelationCollector,
    BreachCollector,
    investigate,
)

__all__ = [
    "EmailValidator",
    "EmailValidationResult",
    "InvalidEmailError",
    "EmailEngine",
    "BaseCollector",
    "ProviderCollector",
    "DomainCollector",
    "ReputationCollector",
    "GravatarCollector",
    "UsernameCorrelationCollector",
    "BreachCollector",
    "investigate",
]
