"""
============================================================
TraceLens Phone Parsing Collector
============================================================

Primary OSINT collector for validating, normalizing, and parsing phone numbers
using Google's phonenumbers library.

Author:
    TraceLens
"""

from typing import Any
from app.osint.modules.phone.base import BasePhoneCollector
from app.osint.modules.phone.validator import PhoneValidationResult


class ParsingCollector(BasePhoneCollector):
    """
    Phone Validation & Parsing Collector.
    Extracts E.164, International, National formats, region, country, timezone, and type.
    """

    def __init__(self):
        super().__init__(
            name="Phone Validation & Parsing Collector",
            category="Validation & Parsing",
            enabled=True
        )

    def collect(self, validation: PhoneValidationResult) -> dict[str, Any]:
        """
        Extracts structural phone metadata from validation.
        """
        return {
            "collector": self.name,
            "category": self.category,
            "status": "success",
            "success": True,
            "original": validation.original_input,
            "normalized": validation.e164_format,
            "country": validation.country_name,
            "country_code": f"+{validation.country_code}",
            "national_number": str(validation.national_number),
            "region": validation.location_name,
            "region_code": validation.region_code,
            "timezone": validation.timezone,
            "type": validation.number_type,
            "number_type": validation.number_type,
            "valid": validation.is_valid,
            "possible": validation.is_possible,
            "is_valid": validation.is_valid,
            "is_possible": validation.is_possible,
            "formats": {
                "e164": validation.e164_format,
                "international": validation.international_format,
                "national": validation.national_format,
            },
        }
