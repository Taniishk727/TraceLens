"""
============================================================
TraceLens Email Reputation OSINT Collector
============================================================

Analyzes deliverability risk, disposable domain status, role address flags,
domain category trust, and calculates an evidence-based email reputation score.

Author:
    TraceLens
"""

import logging
from typing import Any

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import EmailValidationResult, PUBLIC_PROVIDERS, DISPOSABLE_DOMAINS
from app.osint.modules.email.collectors.provider import ROLE_BOXES

logger = logging.getLogger(__name__)


class ReputationCollector(BaseCollector):
    """
    Email Deliverability & Risk Reputation Collector.
    Evaluates disposable domains, functional role boxes, domain trust categories,
    and returns a structured reputation analysis.
    """

    def __init__(self):
        super().__init__(name="Reputation Collector", category="Reputation")

    def detect_role_address(self, local_part: str) -> tuple[bool, str | None]:
        """Detects if local_part is a functional role mailbox."""
        norm = local_part.lower().strip()
        for role in ROLE_BOXES:
            if norm == role or norm.startswith(f"{role}.") or norm.startswith(f"{role}-"):
                return True, role.capitalize()
        return False, None

    def classify_domain(self, domain: str) -> str:
        """Determines domain category: Public, Educational, Government, Business, or Disposable."""
        dom_lower = domain.lower()
        if dom_lower in DISPOSABLE_DOMAINS:
            return "Disposable / Temporary"
        if dom_lower in PUBLIC_PROVIDERS:
            return "Public Provider"

        edu_tlds = (".edu", ".edu.au", ".edu.in", ".ac.uk", ".ac.in", ".edu.sg")
        gov_tlds = (".gov", ".gov.uk", ".gov.in", ".gov.au", ".mil")

        for tld in edu_tlds:
            if dom_lower.endswith(tld):
                return "Educational"

        for tld in gov_tlds:
            if dom_lower.endswith(tld):
                return "Government"

        return "Business / Custom"

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes reputation risk assessment.
        """
        email = validation.email
        domain = validation.domain
        local_part = validation.local_part

        logger.info("[Reputation] Evaluating reputation score for %s", email)

        is_disposable = validation.is_disposable or (domain.lower() in DISPOSABLE_DOMAINS)
        is_role_based, role_name = self.detect_role_address(local_part)
        domain_category = self.classify_domain(domain)

        findings: list[str] = []
        score = 75  # Neutral starting score

        if is_disposable:
            score -= 50
            findings.append("HIGH RISK: Disposable / temporary domain detected.")
        else:
            findings.append("Domain is not listed in disposable domain databases.")

        if is_role_based:
            score -= 15
            findings.append(f"ROLE ADDRESS: Generic functional mailbox ({role_name}).")
        else:
            findings.append("Personal/individual mailbox address structure.")

        if domain_category in ("Educational", "Government"):
            score += 15
            findings.append(f"TRUSTED DOMAIN: Verified {domain_category} top-level domain.")
        elif domain_category == "Business / Custom":
            score += 10
            findings.append("CUSTOM DOMAIN: Business / custom infrastructure domain.")
        elif domain_category == "Public Provider":
            score += 5
            findings.append("PUBLIC PROVIDER: Standard public consumer email service.")

        score = max(0, min(100, score))
        logger.info("[Reputation] Calculated score = %d for %s", score, email)

        return {
            "collector": self.name,
            "status": "completed",
            "reputation_score": score,
            "is_disposable": is_disposable,
            "is_role_based": is_role_based,
            "role_name": role_name,
            "domain_category": domain_category,
            "findings": findings,
            "reason": f"Evaluated deliverability and risk posture. Score: {score}/100.",
        }
