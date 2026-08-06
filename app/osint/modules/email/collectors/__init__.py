"""
TraceLens Email Module Collectors
"""

from app.osint.modules.email.collectors.domain_collector import DomainCollector
from app.osint.modules.email.collectors.verification import VerificationCollector
from app.osint.modules.email.collectors.provider import ProviderCollector
from app.osint.modules.email.collectors.gravatar import GravatarCollector
from app.osint.modules.email.collectors.avatar import AvatarCollector
from app.osint.modules.email.collectors.identity import IdentityCollector
from app.osint.modules.email.collectors.account_presence import AccountPresenceCollector
from app.osint.modules.email.collectors.pgp import PGPCollector
from app.osint.modules.email.collectors.github import GitCollector
from app.osint.modules.email.collectors.breach import BreachCollector
from app.osint.modules.email.collectors.public_search import PublicSearchCollector
from app.osint.modules.email.collectors.reputation import ReputationCollector

__all__ = [
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
]
