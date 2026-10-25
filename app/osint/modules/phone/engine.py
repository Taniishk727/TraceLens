"""
============================================================
TraceLens Phone Investigation Engine
============================================================

Central coordinator for Phone OSINT investigations.
Orchestrates independent collectors (Parsing, Carrier, Risk, Public Search,
Reputation, Export) concurrently and generates standardized summary output.

Author:
    TraceLens
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os
import time
from typing import Any

from app.osint.modules.phone.base import BasePhoneCollector
from app.osint.modules.phone.validator import (
    PhoneValidator,
    PhoneValidationResult,
    InvalidPhoneError,
)
from app.osint.modules.phone.collectors import (
    CarrierCollector,
    RiskCollector,
    PublicSearchCollector,
    ReputationCollector,
    ExportCollector,
    PublicComplaintsCollector,
    TwilioLookupCollector,
)

logger = logging.getLogger(__name__)


class PhoneEngine:
    """
    Central orchestration engine for phone number OSINT investigations.
    Manages collector registration, safe parallel execution, timing, and payload assembly.
    """

    def __init__(self):
        self._collectors: list[BasePhoneCollector] = []

        # Register OSINT collectors
        self.register_collector(CarrierCollector())
        self.register_collector(RiskCollector())
        self.register_collector(PublicSearchCollector())
        self.register_collector(ReputationCollector())
        self.register_collector(ExportCollector())
        self.register_collector(PublicComplaintsCollector())
        self.register_collector(TwilioLookupCollector())

    def register_collector(self, collector: BasePhoneCollector) -> None:
        """Registers a new collector instance into the engine pipeline."""
        if not isinstance(collector, BasePhoneCollector):
            raise TypeError("Collector must inherit from BasePhoneCollector.")
        self._collectors.append(collector)

    def run_collector_safe(
        self, collector: BasePhoneCollector, validation: PhoneValidationResult
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
            logger.error("[PhoneEngine] Collector %s crashed: %s", collector.name, exc, exc_info=True)
            return {
                "collector": collector.name,
                "category": collector.category,
                "status": "failed",
                "execution_time_ms": elapsed_ms,
                "error": str(exc),
                "reason": f"Collector execution failed: {str(exc)}",
            }

    def generate_investigation_summary(
        self,
        validation: PhoneValidationResult,
        carrier_name: str = "Unknown",
        public_search_res: dict[str, Any] | None = None,
        risk_res: dict[str, Any] | None = None,
        reputation_res: dict[str, Any] | None = None,
    ) -> str:
        """
        Generates a clear natural language summary for the investigation result.
        """
        valid_desc = "valid" if validation.is_valid else "invalid"
        type_desc = validation.number_type.lower()
        country_desc = validation.country_name or "Unknown"

        demonym_map = {
            "India": "Indian",
            "United States": "US",
            "United Kingdom": "UK",
            "Canada": "Canadian",
            "Australia": "Australian",
            "Germany": "German",
            "France": "French",
        }
        demonym = demonym_map.get(country_desc, country_desc)

        base = f"This appears to be a {valid_desc} {demonym} {type_desc} number"

        if carrier_name and carrier_name != "Unknown":
            base = f"{base} operating on the {carrier_name} network."
        else:
            base = f"{base}. Carrier information is unavailable."

        # Risk Analysis Assessment
        if risk_res and risk_res.get("status") == "success":
            risk_summary = risk_res.get("summary", "")
            if risk_summary:
                base = f"{base} {risk_summary}"
            else:
                base = f"{base} No significant risk indicators were detected."

        # Reputation Findings
        if reputation_res:
            rep_status = reputation_res.get("reputation")
            total_mentions = reputation_res.get("total_mentions", 0)
            categories = reputation_res.get("categories", {})
            if rep_status == "POTENTIAL_REPORTS" and total_mentions > 0:
                cat_parts = [f"{count} {cat}" for cat, count in categories.items() if count > 0]
                cat_str = f", including {', '.join(cat_parts)}" if cat_parts else ""
                base += f" Public search results contain {total_mentions} reputation-related mention{'s' if total_mentions > 1 else ''}{cat_str}. These reports are unverified."
            elif rep_status == "NO_PUBLIC_REPORTS_FOUND":
                base += " No relevant public reputation reports were discovered in the sources checked."
            elif rep_status == "UNAVAILABLE":
                base += " Public search results were unavailable to evaluate public reputation."

        # Public Search Results
        if public_search_res:
            status = public_search_res.get("status")
            total = public_search_res.get("total_results", 0)
            domains = public_search_res.get("unique_domains_count", 0)
            if status == "success" and total > 0:
                base += f" The number has public web exposure with {total} reference{'s' if total > 1 else ''} across {domains} unique domain{'s' if domains > 1 else ''}."
            elif status == "no_results":
                base += " No publicly indexed references were discovered during the automated public web search."

        return base

    def investigate(self, raw_phone: str) -> dict[str, Any]:
        """
        Main investigation entry-point for Phone OSINT.

        Args:
            raw_phone: Phone number string to investigate.

        Returns:
            Standardized investigation result dictionary.
        """
        start_time = time.perf_counter()

        # 1. Validation & Parsing
        try:
            validation = PhoneValidator.validate(raw_phone)
        except InvalidPhoneError as err:
            return {
                "success": False,
                "module": "Phone",
                "target": raw_phone,
                "error": str(err),
                "details": ["Failed syntax or structural validation."],
            }

        # 2. Pipeline Execution: Stage 1 (Independent), Stage 2 (Reputation), Stage 3 (Risk)
        stage1_collectors = [
            c for c in self._collectors
            if c.enabled and c.name not in ["Reputation Check Collector", "Risk Analysis Collector"]
            and (
                c.name != "Twilio Phone Intelligence"
                or os.environ.get("TRACELENS_PHONE_INTELLIGENCE", "").strip().lower() in {"1", "true", "yes", "on"}
            )
        ]
        reputation_collector = next((c for c in self._collectors if c.enabled and c.name == "Reputation Check Collector"), None)
        risk_collector = next((c for c in self._collectors if c.enabled and c.name == "Risk Analysis Collector"), None)

        collector_results: list[dict[str, Any]] = []

        # Stage 1: Parallel Execution for Primary Collectors
        if stage1_collectors:
            with ThreadPoolExecutor(max_workers=min(8, len(stage1_collectors))) as executor:
                futures = [
                    executor.submit(self.run_collector_safe, collector, validation)
                    for collector in stage1_collectors
                ]
                for future in as_completed(futures):
                    collector_results.append(future.result())

        # Extract Stage 1 outputs
        carrier_res = None
        carrier_name = "Unknown"
        public_search_res = None

        for col_res in collector_results:
            col_name = col_res.get("collector")
            if col_name == "Carrier Intelligence Collector":
                carrier_res = col_res
                if col_res.get("carrier"):
                    carrier_name = col_res.get("carrier")
            elif col_name == "Public Search Collector":
                public_search_res = col_res

        # Stage 2: Reputation Check (Consumes Public Search output)
        reputation_res = None
        if reputation_collector:
            t0 = time.perf_counter()
            try:
                reputation_res = reputation_collector.collect(
                    validation,
                    public_search_res=public_search_res,
                )
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                reputation_res["execution_time_ms"] = elapsed_ms
            except Exception as exc:
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                logger.error("[PhoneEngine] Reputation Check Collector crashed: %s", exc, exc_info=True)
                reputation_res = {
                    "collector": reputation_collector.name,
                    "category": reputation_collector.category,
                    "status": "failed",
                    "execution_time_ms": elapsed_ms,
                    "error": str(exc),
                    "reputation": "UNAVAILABLE",
                    "total_mentions": 0,
                    "sources_checked": 0,
                    "categories": {},
                    "sources": [],
                    "reason": "Reputation check execution failed.",
                }
            collector_results.append(reputation_res)

        # Stage 3: Risk Analysis (Consumes Validation, Carrier, Public Search, and Reputation outputs)
        risk_res = None
        if risk_collector:
            t0 = time.perf_counter()
            try:
                risk_res = risk_collector.collect(
                    validation,
                    carrier_res=carrier_res,
                    public_search_res=public_search_res,
                    reputation_res=reputation_res,
                )
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                risk_res["execution_time_ms"] = elapsed_ms
            except Exception as exc:
                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                logger.error("[PhoneEngine] Risk Analysis Collector crashed: %s", exc, exc_info=True)
                risk_res = {
                    "collector": risk_collector.name,
                    "category": risk_collector.category,
                    "status": "failed",
                    "execution_time_ms": elapsed_ms,
                    "error": str(exc),
                    "score": 0,
                    "level": "UNKNOWN",
                    "summary": "Risk analysis execution failed.",
                }
            collector_results.append(risk_res)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # 3. Generate Summary Text
        summary_text = self.generate_investigation_summary(
            validation, carrier_name, public_search_res, risk_res, reputation_res
        )

        # 5. Standardized Response Payload
        return {
            "success": True,
            "module": "Phone Investigation",
            "status": "completed",
            "target": validation.e164_format,
            "parsed": validation.to_dict(),
            "summary": summary_text,
            "details": {
                "country": validation.country_name,
                "country_code": f"+{validation.country_code}",
                "national_number": str(validation.national_number),
                "region": validation.location_name,
                "timezone": validation.timezone,
                "number_type": validation.number_type,
                "e164_format": validation.e164_format,
                "international_format": validation.international_format,
                "national_format": validation.national_format,
                "is_valid": validation.is_valid,
                "is_possible": validation.is_possible,
                "carrier": carrier_name,
            },
            "metadata": {
                "execution_time_ms": elapsed_ms,
                "total_collectors": len(collector_results),
            },
            "results": collector_results,
        }


# Global engine instance and module interface function
_ENGINE = PhoneEngine()


def investigate(phone_number: str) -> dict[str, Any]:
    """
    Module interface function matching TraceLens investigation dispatcher conventions.
    """
    return _ENGINE.investigate(phone_number)
