"""
============================================================
TraceLens Phone Reputation Check Collector Implementation
============================================================

Dedicated OSINT reputation collector for Phone numbers.
Consumes existing Public Search Collector outputs to identify,
categorize, and aggregate potential public reputation mentions.

Author:
    TraceLens
"""

import logging
from typing import Any, Dict

from app.osint.modules.phone.base import BasePhoneCollector
from app.osint.modules.phone.validator import PhoneValidationResult
from app.osint.modules.phone.collectors.reputation.rules import evaluate_reputation_rules

logger = logging.getLogger(__name__)


class ReputationCollector(BasePhoneCollector):
    """
    Dedicated Phone Reputation Check Collector.
    Evaluates public search results for contextual reputation mentions
    (spam, scam, fraud, robocall, telemarketing, phishing, harassment, suspicious)
    without making duplicate network requests.
    """

    def __init__(self):
        super().__init__(
            name="Reputation Check Collector",
            category="Reputation Check",
            enabled=True
        )

    def collect(
        self,
        validation: PhoneValidationResult,
        public_search_res: Dict[str, Any] | None = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Executes public reputation analysis against Public Search findings.

        Args:
            validation: PhoneValidationResult dataclass instance.
            public_search_res: Optional output dictionary from PublicSearchCollector.

        Returns:
            Structured reputation analysis result dictionary.
        """
        logger.info("[ReputationCollector] Running reputation check for target %s", getattr(validation, "e164_format", "Unknown"))

        eval_res = evaluate_reputation_rules(
            validation=validation,
            public_search_res=public_search_res,
        )

        status = "success" if eval_res["reputation"] != "UNAVAILABLE" else "unavailable"
        success = eval_res["reputation"] != "UNAVAILABLE"

        return {
            "collector": self.name,
            "category": self.category,
            "status": status,
            "success": success,
            "reputation": eval_res["reputation"],
            "reputation_status": eval_res["reputation"],
            "total_mentions": eval_res["total_mentions"],
            "sources_checked": eval_res["sources_checked"],
            "categories": eval_res["categories"],
            "sources": eval_res["sources"],
            "disclaimer": eval_res.get("disclaimer", ""),
            "reason": eval_res.get("reason", ""),
        }
