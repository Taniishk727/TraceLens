"""
============================================================
TraceLens Email Provider Collector
============================================================

Performs email provider classification, role-based address detection,
and domain category identification.

Author:
    TraceLens
"""

import logging
from typing import Any

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import EmailValidationResult, PUBLIC_PROVIDERS

logger = logging.getLogger(__name__)

# Standard functional/role-based mailbox prefixes
ROLE_BOXES: set[str] = {
    "admin",
    "administrator",
    "support",
    "info",
    "information",
    "sales",
    "contact",
    "billing",
    "help",
    "helpdesk",
    "security",
    "office",
    "webmaster",
    "postmaster",
    "hostmaster",
    "marketing",
    "jobs",
    "careers",
    "hr",
    "dev",
    "developer",
    "compliance",
    "legal",
    "service",
    "services",
    "enquiry",
    "enquiries",
    "inquiry",
    "inquiries",
    "team",
    "abuse",
    "privacy",
    "press",
    "media",
    "finance",
    "accounting",
}


class ProviderCollector(BaseCollector):
    """
    Provider & Role-based Address OSINT Collector.
    Identifies primary mail provider, domain categorization (Public vs Business vs Edu vs Gov),
    and checks if email is a functional/role-based address.
    """

    def __init__(self):
        super().__init__(name="Provider Collector", category="Infrastructure")

    def detect_role_based(self, local_part: str) -> tuple[bool, str | None]:
        """Checks if email local_part matches common role-based prefixes."""
        normalized_part = local_part.lower().strip()

        # Direct match or hyphen/dot prefix match (e.g. tech-support, info.user)
        for role in ROLE_BOXES:
            if (
                normalized_part == role
                or normalized_part.startswith(f"{role}.")
                or normalized_part.startswith(f"{role}-")
                or normalized_part.endswith(f".{role}")
                or normalized_part.endswith(f"-{role}")
            ):
                return True, role.capitalize()

        return False, None

    def classify_domain_type(self, domain: str) -> str:
        """Categorizes domain into Public, Educational, Government, or Business/Custom."""
        domain_lower = domain.lower()
        if domain_lower in PUBLIC_PROVIDERS:
            return "Public"

        edu_tlds = (".edu", ".edu.au", ".edu.in", ".ac.uk", ".ac.in", ".edu.cn", ".edu.sg")
        gov_tlds = (".gov", ".gov.uk", ".gov.in", ".gov.au", ".mil", ".gov.br", ".gov.ca")

        for tld in edu_tlds:
            if domain_lower.endswith(tld) or f"{tld}." in domain_lower:
                return "Educational"

        for tld in gov_tlds:
            if domain_lower.endswith(tld) or f"{tld}." in domain_lower:
                return "Government"

        return "Business / Custom"

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes provider classification and role address detection.
        """
        logger.info("[Provider] Analyzing provider for target: %s", validation.email)

        domain_category = self.classify_domain_type(validation.domain)
        is_role_based, role_name = self.detect_role_based(validation.local_part)

        if is_role_based:
            logger.info("[Provider] Role-based address detected (%s)", role_name)
        else:
            logger.info("[Provider] Personal/individual local-part detected")

        return {
            "collector": self.name,
            "status": "completed",
            "provider": validation.provider,
            "provider_type": domain_category,
            "is_role_based": is_role_based,
            "role_name": role_name,
            "is_disposable": validation.is_disposable,
        }
