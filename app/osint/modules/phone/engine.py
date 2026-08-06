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
import time
from typing import Any

from app.osint.modules.phone.base import BasePhoneCollector
from app.osint.modules.phone.validator import (
    PhoneValidator,
    PhoneValidationResult,
    InvalidPhoneError,
)
from app.osint.modules.phone.collectors import (
    ParsingCollector,
    CarrierCollector,
    RiskCollector,
    PublicSearchCollector,
    ReputationCollector,
    ExportCollector,
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
        self.register_collector(ParsingCollector())
        self.register_collector(CarrierCollector())
        self.register_collector(RiskCollector())
        self.register_collector(PublicSearchCollector())
        self.register_collector(ReputationCollector())
        self.register_collector(ExportCollector())

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

    def generate_investigation_summary(self, validation: PhoneValidationResult) -> str:
        """
        Generates a clear natural language summary for the investigation result.
        Example: "Valid mobile number from India. Country code: +91. Timezone: Asia/Kolkata. Phone number successfully parsed."
        """
        valid_desc = "Valid" if validation.is_valid else "Invalid"
        type_desc = validation.number_type.lower().replace("_", " ")
        country_desc = validation.country_name or "Unknown Country"
        code_desc = f"+{validation.country_code}"
        tz_desc = validation.timezone or "Unknown Timezone"

        return f"{valid_desc} {type_desc} number from {country_desc}. Country code: {code_desc}. Timezone: {tz_desc}. Phone number successfully parsed."

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

        # 2. Concurrent Collector Execution
        active_collectors = [c for c in self._collectors if c.enabled]
        collector_results: list[dict[str, Any]] = []

        if active_collectors:
            with ThreadPoolExecutor(max_workers=min(8, len(active_collectors))) as executor:
                futures = [
                    executor.submit(self.run_collector_safe, collector, validation)
                    for collector in active_collectors
                ]
                for future in as_completed(futures):
                    collector_results.append(future.result())

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # 3. Generate Summary Text
        summary_text = self.generate_investigation_summary(validation)

        # 4. Standardized Response Payload
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
            },
            "metadata": {
                "execution_time_ms": elapsed_ms,
                "total_collectors": len(active_collectors),
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
