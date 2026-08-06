"""
============================================================
TraceLens Email Investigation Engine
============================================================

Central coordinator for Email OSINT investigations.
Orchestrates independent collectors (Verification, Provider, Domain,
Gravatar, Git, PGP, Breach, Public Search, Reputation) concurrently.

Execution Flow:
    Raw Email Input
        ↓
    EmailValidator Parsing & Syntax Check
        ↓
    Concurrent Execution of Registered Collectors
        ↓
    Automatic Execution Time Measurement & Failure Isolation
        ↓
    Summary Metrics Assembly & Payload Normalization
        ↓
    Return Standardized Email OSINT Result

Author:
    TraceLens
"""

from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time
from typing import Any

from app.osint.modules.email.validator import (
    EmailValidator,
    EmailValidationResult,
    InvalidEmailError,
)
from app.osint.modules.email.collectors import (
    VerificationCollector,
    ProviderCollector,
    DomainCollector,
    ReputationCollector,
    AccountPresenceCollector,
    IdentityCollector,
    AvatarCollector,
    GitCollector,
    PGPCollector,
    PublicSearchCollector,
    BreachCollector,
)

logger = logging.getLogger(__name__)


from app.osint.modules.email.base import BaseCollector



from app.osint.modules.email.identity_processor import process_email_identity


# ==========================================================
# EMAIL INVESTIGATION ENGINE
# ==========================================================

class EmailEngine:
    """
    Central orchestration engine for email investigations.
    Manages collector registration, safe parallel execution, and timing.
    """

    def __init__(self):
        self._collectors: list[BaseCollector] = []

        # Register default OSINT collectors
        self.register_collector(VerificationCollector())
        self.register_collector(ProviderCollector())
        self.register_collector(DomainCollector())
        self.register_collector(ReputationCollector())
        self.register_collector(AccountPresenceCollector())
        self.register_collector(IdentityCollector())
        self.register_collector(AvatarCollector())
        self.register_collector(GitCollector())
        self.register_collector(PGPCollector())
        self.register_collector(PublicSearchCollector())
        self.register_collector(BreachCollector())

    def register_collector(self, collector: BaseCollector) -> None:
        """Registers a new collector instance into the engine pipeline."""
        if not isinstance(collector, BaseCollector):
            raise TypeError("Collector must inherit from BaseCollector.")
        self._collectors.append(collector)

    def run_collector_safe(
        self, collector: BaseCollector, validation: EmailValidationResult
    ) -> dict[str, Any]:
        """Executes a single collector safely, recording execution time and handling errors."""
        t0 = time.perf_counter()
        try:
            res = collector.collect(validation)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            res["execution_time_ms"] = elapsed_ms
            return res
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            logger.error("[Engine] Collector %s crashed: %s", collector.name, exc, exc_info=True)
            return {
                "collector": collector.name,
                "status": "failed",
                "execution_time_ms": elapsed_ms,
                "error": str(exc),
                "reason": f"Collector execution failed: {str(exc)}",
            }

    def investigate(self, raw_email: str) -> dict[str, Any]:
        """
        Main investigation entry-point.

        Args:
            raw_email: Email address string to investigate.

        Returns:
            Standardized investigation result dictionary.
        """
        start_time = time.perf_counter()

        # 1. Validation & Parsing
        try:
            validation = EmailValidator.validate(raw_email)
        except InvalidEmailError as err:
            return {
                "success": False,
                "module": "Email",
                "target": raw_email,
                "error": str(err),
                "details": ["Failed syntax or structural validation."],
            }

        # 2. Run Collectors Concurrently
        active_collectors = [c for c in self._collectors if c.enabled]
        collector_results: list[dict[str, Any]] = []

        if active_collectors:
            with ThreadPoolExecutor(max_workers=min(12, len(active_collectors))) as executor:
                futures = [
                    executor.submit(self.run_collector_safe, collector, validation)
                    for collector in active_collectors
                ]
                for future in as_completed(futures):
                    collector_results.append(future.result())

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # 3. Extract Summary Metrics from Collector Findings
        mailbox_status = "Unknown"
        confidence_score = 0
        is_role_based = False
        role_name = None

        for col in collector_results:
            name = col.get("collector")
            if name == "Verification Collector":
                mailbox_status = col.get("mailbox_status", "Unknown")
                confidence_score = col.get("confidence_score", 0)
            elif name in ("Provider Collector", "Reputation Collector"):
                if col.get("is_role_based"):
                    is_role_based = True
                    role_name = col.get("role_name")

        # 4. Identity Intelligence Post-Processing
        identity_intel = process_email_identity(collector_results, validation.email)

        # 5. Assemble Standardized Response Payload
        return {
            "success": True,
            "module": "Email Investigation",
            "status": "completed",
            "target": validation.email,
            "parsed": validation.to_dict(),
            "summary": {
                "normalized_email": validation.email,
                "local_part": validation.local_part,
                "domain": validation.domain,
                "provider": validation.provider,
                "provider_type": validation.provider_type,
                "mailbox_status": mailbox_status,
                "confidence_score": confidence_score,
                "is_role_based": is_role_based,
                "role_name": role_name,
                "is_disposable": validation.is_disposable,
                "total_collectors": len(active_collectors),
            },
            "identity_summary": identity_intel["identity_summary"],
            "evidence": identity_intel["evidence"],
            "public_avatar": identity_intel["public_avatar"],
            "discovered_usernames": identity_intel["discovered_usernames"],
            "username_candidates": identity_intel["username_candidates"],
            "timeline": identity_intel["timeline"],
            "future_providers": identity_intel["future_providers"],
            "metadata": {
                "execution_time_ms": elapsed_ms,
                "collectors_run": len(collector_results),
            },
            "results": collector_results,
        }


# Global engine instance and module function alias
_ENGINE = EmailEngine()


def investigate(email_address: str) -> dict[str, Any]:
    """
    Module interface function matching TraceLens investigation dispatcher conventions.
    """
    return _ENGINE.investigate(email_address)
