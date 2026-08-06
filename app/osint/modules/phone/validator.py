"""
============================================================
TraceLens Phone Validator
============================================================

Responsible for parsing, syntax/structure validation, E.164 normalization,
and metadata extraction of phone numbers using Google's phonenumbers library.

Author:
    TraceLens
"""

from dataclasses import dataclass, asdict
import re
from typing import Any, Optional
import phonenumbers
from phonenumbers import geocoder, carrier, timezone, NumberParseException


class InvalidPhoneError(ValueError):
    """Raised when a phone number fails syntax, length, or structural validation."""
    pass


@dataclass(frozen=True)
class PhoneValidationResult:
    """Structured result containing parsed and validated phone metadata."""

    original_input: str
    phone: str
    e164_format: str
    international_format: str
    national_format: str
    country_code: int
    national_number: int
    country_name: str
    region_code: str
    location_name: str
    timezone: str
    number_type: str
    is_valid: bool
    is_possible: bool
    error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Returns result as a dictionary."""
        return asdict(self)


NUMBER_TYPE_MAP = {
    phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
    phonenumbers.PhoneNumberType.MOBILE: "Mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
    phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
    phonenumbers.PhoneNumberType.VOIP: "VoIP",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
    phonenumbers.PhoneNumberType.PAGER: "Pager",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "Unknown",
}


class PhoneValidator:
    """
    Validates, parses, and normalizes phone numbers into E.164 and international formats.
    Utilizes Google's phonenumbers library.
    """

    @classmethod
    def sanitize(cls, raw_phone: str) -> str:
        """
        Strips surrounding whitespace and normalizes internal formatting characters.
        Preserves leading '+' if present.
        """
        if not raw_phone or not isinstance(raw_phone, str):
            raise InvalidPhoneError("Phone number input must be a non-empty string.")

        cleaned = raw_phone.strip()
        if not cleaned:
            raise InvalidPhoneError("Phone number cannot be empty or whitespace.")

        # Keep leading '+' if present, remove non-digit chars except '+'
        has_plus = cleaned.startswith("+")
        digits_only = re.sub(r"[^\d]", "", cleaned)

        if not digits_only:
            raise InvalidPhoneError("Phone number contains no valid numeric digits.")

        return f"+{digits_only}" if has_plus else digits_only

    @classmethod
    def validate(cls, raw_phone: str, default_region: str = "IN") -> PhoneValidationResult:
        """
        Validates, parses, and normalizes a raw phone string using Google's phonenumbers library.

        Args:
            raw_phone: Raw phone number input string.
            default_region: ISO 2-letter default country code if missing '+' prefix (default "IN").

        Returns:
            PhoneValidationResult dataclass.
        """
        sanitized = cls.sanitize(raw_phone)

        # Minimum digit length check
        digit_count = len(re.sub(r"[^\d]", "", sanitized))
        if digit_count < 7 or digit_count > 15:
            raise InvalidPhoneError(f"Phone number must contain between 7 and 15 digits (got {digit_count}).")

        # Parse with phonenumbers
        try:
            if sanitized.startswith("+"):
                parsed_num = phonenumbers.parse(sanitized, None)
            else:
                parsed_num = phonenumbers.parse(sanitized, default_region)
        except NumberParseException as err:
            raise InvalidPhoneError(f"Failed to parse phone number: {err}")

        is_valid = phonenumbers.is_valid_number(parsed_num)
        is_possible = phonenumbers.is_possible_number(parsed_num)

        if not is_possible:
            raise InvalidPhoneError("Phone number structure is impossible for any known region.")

        if not is_valid:
            raise InvalidPhoneError(f"Invalid phone number structure for region '{phonenumbers.region_code_for_number(parsed_num) or default_region}'.")

        # Format representations
        e164_fmt = phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.E164)
        intl_fmt = phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nat_fmt = phonenumbers.format_number(parsed_num, phonenumbers.PhoneNumberFormat.NATIONAL)

        # Geocoder & metadata extraction
        reg_code = phonenumbers.region_code_for_number(parsed_num) or "GLOBAL"
        country_desc = geocoder.country_name_for_number(parsed_num, "en") or reg_code
        location_desc = geocoder.description_for_number(parsed_num, "en") or country_desc

        # Timezones
        tz_list = timezone.time_zones_for_number(parsed_num)
        tz_str = ", ".join(tz_list) if tz_list else "Unknown"

        # Number type
        num_type_enum = phonenumbers.number_type(parsed_num)
        num_type_str = NUMBER_TYPE_MAP.get(num_type_enum, "Unknown")

        return PhoneValidationResult(
            original_input=raw_phone.strip(),
            phone=e164_fmt,
            e164_format=e164_fmt,
            international_format=intl_fmt,
            national_format=nat_fmt,
            country_code=parsed_num.country_code,
            national_number=parsed_num.national_number,
            country_name=country_desc,
            region_code=reg_code,
            location_name=location_desc,
            timezone=tz_str,
            number_type=num_type_str,
            is_valid=is_valid,
            is_possible=is_possible,
            error=None
        )
