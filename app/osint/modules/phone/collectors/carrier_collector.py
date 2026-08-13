"""
============================================================
TraceLens Carrier Intelligence Collector
============================================================

Extracts carrier name, telecommunication provider, and network type classification
(Mobile Network vs. Landline Network) using Google's phonenumbers library.

Author:
    TraceLens
"""

import logging
from typing import Any
import phonenumbers
from phonenumbers import carrier

from app.osint.modules.phone.base import BasePhoneCollector
from app.osint.modules.phone.validator import PhoneValidationResult

logger = logging.getLogger(__name__)


class CarrierCollector(BasePhoneCollector):
    """
    Carrier Intelligence Collector.
    Consumes parsed phone object to extract carrier name and network type classification.
    """

    def __init__(self):
        super().__init__(
            name="Carrier Intelligence Collector",
            category="Carrier Intelligence",
            enabled=True
        )

    def classify_network(self, number_type: str) -> str:
        """
        Classifies number type into readable network category.
        """
        if number_type in ["Mobile", "Fixed Line or Mobile"]:
            return "Mobile Network"
        elif number_type == "Fixed Line":
            return "Landline Network"
        elif number_type == "VoIP":
            return "VoIP Network"
        elif number_type in ["Toll Free", "Premium Rate", "Shared Cost", "UAN"]:
            return "Special Services Network"
        return "Unknown Network"

    def collect(self, validation: PhoneValidationResult) -> dict[str, Any]:
        """
        Extracts carrier name and network classification from parsed phone object.
        """
        carrier_name = "Unknown"

        try:
            if validation.carrier_name:
                carrier_name = validation.carrier_name.strip()
            else:
                # Fallback parse via phonenumbers.carrier
                if validation.e164_format.startswith("+"):
                    parsed_num = phonenumbers.parse(validation.e164_format, None)
                else:
                    parsed_num = phonenumbers.parse(validation.e164_format, validation.region_code)
                c_name = carrier.name_for_number(parsed_num, "en")
                if c_name and c_name.strip():
                    carrier_name = c_name.strip()
        except Exception as exc:
            logger.warning("[CarrierCollector] Error retrieving carrier name: %s", exc)

        network_classification = self.classify_network(validation.number_type)

        return {
            "collector": self.name,
            "category": self.category,
            "status": "success",
            "success": True,
            "carrier": carrier_name,
            "network": network_classification,
            "number_type": validation.number_type,
            "country": validation.country_name,
            "country_code": f"+{validation.country_code}",
            "region": validation.location_name,
        }
