"""Opt-in Twilio Lookup enrichment for line, fraud, and caller-name signals."""

from datetime import datetime, timezone
import os
from typing import Any
from urllib.parse import quote

import requests

from app.osint.modules.phone.base import BasePhoneCollector
from app.osint.modules.phone.validator import PhoneValidationResult


class TwilioLookupCollector(BasePhoneCollector):
    """Query Twilio's paid Lookup data packages only when explicitly enabled."""

    FIELDS = (
        "line_type_intelligence",
        "line_status",
        "caller_name",
        "sim_swap",
        "sms_pumping_risk",
        "phone_number_quality_score",
    )

    def __init__(self, timeout: float = 12.0):
        super().__init__(name="Twilio Phone Intelligence", category="Carrier and Risk Intelligence")
        self.timeout = timeout

    @staticmethod
    def _last_verified_date() -> str | None:
        value = os.environ.get("TRACELENS_PHONE_LAST_VERIFIED_DATE", "").strip()
        if not value:
            return None
        try:
            datetime.strptime(value, "%Y%m%d")
        except ValueError as exc:
            raise ValueError("TRACELENS_PHONE_LAST_VERIFIED_DATE must use YYYYMMDD format.") from exc
        return value

    def collect(self, validation: PhoneValidationResult) -> dict[str, Any]:
        api_key = os.environ.get("TWILIO_API_KEY", "").strip()
        api_secret = os.environ.get("TWILIO_API_SECRET", "").strip()
        if not api_key or not api_secret:
            return {
                "collector": self.name,
                "category": self.category,
                "status": "not_configured",
                "reason": "Set TWILIO_API_KEY and TWILIO_API_SECRET to enable paid phone intelligence.",
            }

        fields = list(self.FIELDS)
        params: dict[str, str] = {"Fields": ",".join(fields)}
        try:
            last_verified_date = self._last_verified_date()
            if last_verified_date:
                fields.append("reassigned_number")
                params["Fields"] = ",".join(fields)
                params["LastVerifiedDate"] = last_verified_date
        except ValueError as exc:
            return {
                "collector": self.name,
                "category": self.category,
                "status": "invalid_configuration",
                "reason": str(exc),
            }

        encoded_number = quote(validation.e164_format, safe="")
        url = f"https://lookups.twilio.com/v2/PhoneNumbers/{encoded_number}"
        try:
            response = requests.get(
                url,
                params=params,
                auth=(api_key, api_secret),
                timeout=self.timeout,
            )
            response.raise_for_status()
            payload = response.json()
            signals = {
                field: payload.get(field)
                for field in fields
                if payload.get(field) is not None
            }
            return {
                "collector": self.name,
                "category": self.category,
                "status": "success" if signals else "no_data",
                "source": "Twilio Lookup v2",
                "fields_requested": fields,
                "signals": signals,
                "source_url": "https://www.twilio.com/docs/lookup/v2-api",
                "retrieved_at_utc": datetime.now(timezone.utc).isoformat(),
                "coverage_note": "Returned signals can be null when the carrier/country is unsupported or the package is not enabled.",
                "cost_notice": "Requested data packages may incur per-request charges; coverage and access vary by country and carrier.",
                "caller_name_notice": "Caller name is a CNAM listing, available only for supported US numbers; it is not proof of identity or ownership.",
            }
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            return {
                "collector": self.name,
                "category": self.category,
                "status": "unavailable",
                "source": "Twilio Lookup v2",
                "http_status": status_code,
                "reason": "Lookup failed or one or more requested packages are not enabled for this account/number.",
            }
        except (requests.RequestException, ValueError) as exc:
            return {
                "collector": self.name,
                "category": self.category,
                "status": "unavailable",
                "source": "Twilio Lookup v2",
                "reason": str(exc),
            }
