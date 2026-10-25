"""Free US number enrichment from public numbering and complaint data."""

from datetime import datetime, timezone
from typing import Any

import requests

from app.osint.modules.phone.base import BasePhoneCollector
from app.osint.modules.phone.validator import PhoneValidationResult


class PublicComplaintsCollector(BasePhoneCollector):
    """Fetch public US carrier/assignment and FTC complaint summary data."""

    def __init__(self, timeout: float = 8.0):
        super().__init__(name="US Public Number Reports", category="Public Records")
        self.timeout = timeout

    def collect(self, validation: PhoneValidationResult) -> dict[str, Any]:
        if validation.region_code != "US":
            return {
                "collector": self.name,
                "category": self.category,
                "status": "not_applicable",
                "reason": "The free public complaint dataset is limited to US numbers.",
            }
        digits = "".join(character for character in validation.e164_format if character.isdigit())
        if not digits.startswith("1") or len(digits) != 11:
            return {
                "collector": self.name,
                "category": self.category,
                "status": "not_applicable",
                "reason": "The free public complaint dataset covers US 10-digit numbers only.",
            }

        number = digits[1:]
        url = f"https://www.usacallerlookup.com/wp-json/ucl/v1/number/{number}"
        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 404:
                return {
                    "collector": self.name,
                    "category": self.category,
                    "status": "no_results",
                    "source": "USACallerLookup (FTC complaints and NANPA numbering data)",
                    "url": url,
                    "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
                    "complaint_count": 0,
                    "note": "No matching public report was returned; this does not prove the number is safe.",
                }
            response.raise_for_status()
            payload = response.json()
            return {
                "collector": self.name,
                "category": self.category,
                "status": "success",
                "source": "USACallerLookup (FTC complaints and NANPA numbering data)",
                "url": payload.get("attribution", {}).get("url", url) if isinstance(payload, dict) else url,
                "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
                "complaint_data_freshness": "FTC complaint data is refreshed each weekday, according to the provider.",
                "data": payload,
                "interpretation": "A complaint is an unverified report and caller ID can be spoofed.",
            }
        except (requests.RequestException, ValueError) as exc:
            return {
                "collector": self.name,
                "category": self.category,
                "status": "unavailable",
                "source": "USACallerLookup (FTC complaints and NANPA numbering data)",
                "reason": str(exc),
            }
