"""
============================================================
TraceLens Email Validator
============================================================

Responsible ONLY for parsing, syntax validation, and metadata extraction
of email addresses without performing any network requests.

Author:
    TraceLens
"""

from dataclasses import dataclass, asdict
import email.utils
import re


class InvalidEmailError(ValueError):
    """Raised when an email address fails syntax or format validation."""
    pass


@dataclass(frozen=True)
class EmailValidationResult:
    """Structured result containing parsed and validated email metadata."""

    email: str
    local_part: str
    domain: str
    is_valid: bool
    provider: str
    provider_type: str
    is_disposable: bool

    def to_dict(self) -> dict:
        """Returns result as a dictionary."""
        return asdict(self)


# Public Email Provider Mapping: domain -> Provider Name
PUBLIC_PROVIDERS: dict[str, str] = {
    "gmail.com": "Google Workspace / Gmail",
    "googlemail.com": "Google Workspace / Gmail",
    "outlook.com": "Microsoft Outlook",
    "hotmail.com": "Microsoft Hotmail",
    "live.com": "Microsoft Live",
    "msn.com": "Microsoft MSN",
    "yahoo.com": "Yahoo Mail",
    "ymail.com": "Yahoo Mail",
    "rocketmail.com": "Yahoo Mail",
    "proton.me": "Proton Mail",
    "protonmail.com": "Proton Mail",
    "pm.me": "Proton Mail",
    "icloud.com": "Apple iCloud",
    "me.com": "Apple MobileMe",
    "mac.com": "Apple Mac Mail",
    "zoho.com": "Zoho Mail",
    "zohomail.com": "Zoho Mail",
    "aol.com": "AOL Mail",
    "gmx.com": "GMX Mail",
    "gmx.net": "GMX Mail",
    "mail.com": "Mail.com",
    "yandex.com": "Yandex Mail",
    "yandex.ru": "Yandex Mail",
    "fastmail.com": "Fastmail",
    "tuta.io": "Tuta",
    "tutamail.com": "Tuta",
    "tutanota.com": "Tutanota",
}

from pathlib import Path


def load_disposable_domains() -> set[str]:
    """Loads disposable domain list from data/disposable_domains.txt dataset."""
    data_file = Path(__file__).parent / "data" / "disposable_domains.txt"
    if not data_file.exists():
        return set()
    with open(data_file, "r", encoding="utf-8") as f:
        return {
            line.strip().lower()
            for line in f
            if line.strip() and not line.startswith("#")
        }


DISPOSABLE_DOMAINS: set[str] = load_disposable_domains()


class EmailValidator:
    """
    Validates and normalizes email addresses and extracts domain metadata.
    Does not perform any DNS, network, or external API calls.
    """

    # RFC 5322 compliant regex pattern for syntax validation
    EMAIL_REGEX = re.compile(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
    )

    @classmethod
    def normalize(cls, raw_email: str) -> str:
        """Strips whitespace and converts email address to lowercase."""
        if not raw_email or not isinstance(raw_email, str):
            raise InvalidEmailError("Email input must be a non-empty string.")

        cleaned = raw_email.strip().lower()
        if not cleaned:
            raise InvalidEmailError("Email address cannot be empty or whitespace.")
        return cleaned

    @classmethod
    def parse_parts(cls, normalized_email: str) -> tuple[str, str]:
        """Extracts local_part and domain from normalized email address."""
        if "@" not in normalized_email:
            raise InvalidEmailError("Email address missing '@' symbol.")

        parts = normalized_email.rsplit("@", 1)
        if len(parts) != 2:
            raise InvalidEmailError("Invalid email structure.")

        local_part, domain = parts[0], parts[1]

        if not local_part:
            raise InvalidEmailError("Email local part is empty.")
        if not domain:
            raise InvalidEmailError("Email domain part is empty.")
        if "." not in domain:
            raise InvalidEmailError("Email domain must contain a TLD dot extension.")

        return local_part, domain

    @classmethod
    def validate_syntax(cls, email_str: str) -> bool:
        """Validates syntax using standard library parser and RFC 5322 regex."""
        name, addr = email.utils.parseaddr(email_str)
        if not addr or "@" not in addr:
            return False

        return cls.EMAIL_REGEX.match(addr) is not None

    @classmethod
    def validate(cls, raw_email: str) -> EmailValidationResult:
        """
        Validates, normalizes, and parses raw email string.

        Raises:
            InvalidEmailError: If email syntax or structure is invalid.

        Returns:
            EmailValidationResult structured dataclass.
        """
        normalized = cls.normalize(raw_email)

        if not cls.validate_syntax(normalized):
            raise InvalidEmailError(f"Invalid email syntax: '{raw_email}'")

        local_part, domain = cls.parse_parts(normalized)

        # Detect provider name and type
        if domain in PUBLIC_PROVIDERS:
            provider = PUBLIC_PROVIDERS[domain]
            provider_type = "public"
        else:
            provider = f"Custom ({domain})"
            provider_type = "business"

        # Check disposable domain list
        is_disposable = domain in DISPOSABLE_DOMAINS

        return EmailValidationResult(
            email=normalized,
            local_part=local_part,
            domain=domain,
            is_valid=True,
            provider=provider,
            provider_type=provider_type,
            is_disposable=is_disposable,
        )
