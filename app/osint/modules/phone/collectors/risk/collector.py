"""
============================================================
TraceLens Phone Risk Collector Implementation
============================================================

Dedicated OSINT risk analysis collector for Phone numbers.
Consumes Validation, Carrier, and Public Search collector outputs
to calculate deterministic risk scores and indicator assessments.

Author:
    TraceLens
"""

import logging
from typing import Any, Dict

from app.osint.modules.phone.base import BasePhoneCollector
from app.osint.modules.phone.validator import PhoneValidationResult
from app.osint.modules.phone.collectors.risk.rules import evaluate_risk_rules

logger = logging.getLogger(__name__)


class RiskCollector(BasePhoneCollector):
    """
    Dedicated Phone Risk Analysis Collector.
    Evaluates validated phone metadata, carrier info, and public exposure
    against deterministic risk rules without repeating network requests.
    """

    def __init__(self):
        super().__init__(
            name="Risk Analysis Collector",
            category="Risk Analysis",
            enabled=True
        )

    def collect(
        self,
        validation: PhoneValidationResult,
        carrier_res: Dict[str, Any] | None = None,
        public_search_res: Dict[str, Any] | None = None,
        reputation_res: Dict[str, Any] | None = None,
        **kwargs: Any
    ) -> Dict[str, Any]:
        """
        Executes risk calculation and indicator evaluation.

        Args:
            validation: PhoneValidationResult dataclass instance.
            carrier_res: Optional output dictionary from CarrierCollector.
            public_search_res: Optional output dictionary from PublicSearchCollector.
            reputation_res: Optional output dictionary from ReputationCollector.

        Returns:
            Structured risk assessment result dictionary.
        """
        logger.info("[RiskCollector] Running risk evaluation for target %s", getattr(validation, "e164_format", "Unknown"))

        eval_res = evaluate_risk_rules(
            validation=validation,
            carrier_res=carrier_res,
            public_search_res=public_search_res,
            reputation_res=reputation_res,
        )

        return {
            "collector": self.name,
            "category": self.category,
            "status": "success",
            "success": True,
            "score": eval_res["score"],
            "risk_score": eval_res["score"],
            "level": eval_res["level"],
            "risk_level": eval_res["level"],
            "indicators": eval_res["indicators"],
            "positive_findings": eval_res["positive_findings"],
            "risk_findings": eval_res["risk_findings"],
            "public_exposure": eval_res["public_exposure"],
            "summary": eval_res["summary"],
        }
