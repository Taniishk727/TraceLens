"""
============================================================
TraceLens Domain OSINT Collector
============================================================

Performs real domain intelligence, DNS lookups (MX, TXT, NS, A),
email security posture detection (SPF, DMARC, DKIM), primary mail provider
identification, and disposable domain checking.

Author:
    TraceLens
"""

import logging
from typing import Any
import dns.resolver
import dns.exception

from app.osint.modules.email.engine import BaseCollector
from app.osint.modules.email.validator import (
    EmailValidationResult,
    PUBLIC_PROVIDERS,
    DISPOSABLE_DOMAINS,
)

logger = logging.getLogger(__name__)


# Known Mail Server Hostname Fingerprints -> Mail Provider Name
MX_PROVIDER_FINGERPRINTS: list[tuple[str, str]] = [
    ("google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("aspmx.l.google.com", "Google Workspace"),
    ("outlook.com", "Microsoft 365 / Exchange"),
    ("protection.outlook.com", "Microsoft 365 / Exchange"),
    ("hotmail.com", "Microsoft 365 / Exchange"),
    ("zoho.com", "Zoho Mail"),
    ("zohomail.com", "Zoho Mail"),
    ("protonmail.ch", "Proton Mail"),
    ("proton.me", "Proton Mail"),
    ("icloud.com", "Apple iCloud Mail"),
    ("apple.com", "Apple iCloud Mail"),
    ("yahoo.com", "Yahoo Mail"),
    ("yahoodns.net", "Yahoo Mail"),
    ("mimecast.com", "Mimecast Email Security"),
    ("pphosted.com", "Proofpoint Email Security"),
    ("barracudanetworks.com", "Barracuda Email Security"),
    ("fastmail.com", "Fastmail"),
    ("yandex.net", "Yandex Mail"),
    ("yandex.ru", "Yandex Mail"),
    ("tutanota.com", "Tuta"),
    ("tuta.io", "Tuta"),
]

# Common DKIM Selector Strings to test
COMMON_DKIM_SELECTORS: list[str] = [
    "google",
    "k1",
    "selector1",
    "default",
    "s1",
    "s2021",
    "s2022",
    "mail",
    "ms",
    "zoho",
    "protonmail",
]


class DomainCollector(BaseCollector):
    """
    Domain Intelligence Collector.
    Executes DNS queries for MX, TXT, NS, and A records, analyzes email security posture
    (SPF, DMARC, DKIM), identifies primary mail providers, and checks disposable status.
    """

    def __init__(self, dns_timeout: float = 3.0):
        super().__init__(name="Domain Collector", category="Infrastructure")
        self.dns_timeout = dns_timeout

    def _get_resolver(self) -> dns.resolver.Resolver:
        """Returns a configured dnspython resolver with strict timeouts."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.dns_timeout
        resolver.timeout = self.dns_timeout
        return resolver

    def classify_domain_type(self, domain: str) -> str:
        """Determines domain category (Public, Educational, Government, or Business/Custom)."""
        if domain in PUBLIC_PROVIDERS:
            return "Public"

        domain_lower = domain.lower()
        edu_tlds = (".edu", ".edu.au", ".edu.in", ".ac.uk", ".ac.in", ".edu.cn", ".edu.sg")
        gov_tlds = (".gov", ".gov.uk", ".gov.in", ".gov.au", ".mil", ".gov.br", ".gov.ca")

        for tld in edu_tlds:
            if domain_lower.endswith(tld) or f"{tld}." in domain_lower:
                return "Educational"

        for tld in gov_tlds:
            if domain_lower.endswith(tld) or f"{tld}." in domain_lower:
                return "Government"

        return "Business / Custom"

    def identify_mail_provider(self, domain: str, mx_records: list[dict[str, Any]]) -> str:
        """Identifies primary mail provider based on MX exchange hosts or public provider mapping."""
        # 1. Match MX hostnames against known fingerprints
        for mx in mx_records:
            exchange = mx.get("exchange", "").lower()
            for pattern, provider_name in MX_PROVIDER_FINGERPRINTS:
                if pattern in exchange:
                    return provider_name

        # 2. Check public provider mapping
        if domain in PUBLIC_PROVIDERS:
            return PUBLIC_PROVIDERS[domain]

        # 3. If MX records exist but unrecognized
        if mx_records:
            return f"Custom / Self-Hosted ({mx_records[0]['exchange']})"

        return "None (No MX Records)"

    def resolve_mx(self, domain: str) -> list[dict[str, Any]]:
        """Resolves MX records for domain."""
        resolver = self._get_resolver()
        mx_records = []
        try:
            answers = resolver.resolve(domain, "MX")
            for rdata in answers:
                exchange_str = str(rdata.exchange).rstrip(".").lower()
                mx_records.append({
                    "exchange": exchange_str,
                    "preference": rdata.preference,
                })
            mx_records.sort(key=lambda x: x["preference"])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout) as exc:
            logger.debug("MX lookup for %s failed: %s", domain, exc)
        except Exception as exc:
            logger.warning("Unexpected error during MX lookup for %s: %s", domain, exc)
        return mx_records

    def resolve_txt(self, domain: str) -> list[str]:
        """Resolves TXT records for domain."""
        resolver = self._get_resolver()
        txt_records = []
        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                txt_records.append(txt_str)
        except Exception as exc:
            logger.debug("TXT lookup for %s failed: %s", domain, exc)
        return txt_records

    def resolve_ns(self, domain: str) -> list[str]:
        """Resolves NS records for domain."""
        resolver = self._get_resolver()
        ns_records = []
        try:
            answers = resolver.resolve(domain, "NS")
            for rdata in answers:
                ns_records.append(str(rdata.target).rstrip(".").lower())
        except Exception as exc:
            logger.debug("NS lookup for %s failed: %s", domain, exc)
        return ns_records

    def resolve_a(self, domain: str) -> list[str]:
        """Resolves IPv4 A records for domain."""
        resolver = self._get_resolver()
        a_records = []
        try:
            answers = resolver.resolve(domain, "A")
            for rdata in answers:
                a_records.append(str(rdata.address))
        except Exception as exc:
            logger.debug("A record lookup for %s failed: %s", domain, exc)
        return a_records

    def detect_spf(self, txt_records: list[str]) -> tuple[bool, str | None]:
        """Detects presence of SPF record in TXT records."""
        for txt in txt_records:
            if txt.startswith("v=spf1") or "v=spf1" in txt:
                return True, txt
        return False, None

    def detect_dmarc(self, domain: str) -> tuple[bool, str | None]:
        """Queries _dmarc.{domain} for DMARC TXT record."""
        resolver = self._get_resolver()
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                if "v=DMARC1" in txt_str or txt_str.startswith("v=DMARC1"):
                    return True, txt_str
        except Exception as exc:
            logger.debug("DMARC lookup for %s failed: %s", dmarc_domain, exc)
        return False, None

    def detect_dkim(self, domain: str) -> str:
        """Checks common DKIM selectors for DKIM TXT record availability."""
        resolver = self._get_resolver()
        resolver.lifetime = 1.0
        resolver.timeout = 1.0
        for selector in COMMON_DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{domain}"
            try:
                answers = resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                    if "v=DKIM1" in txt_str or "p=" in txt_str:
                        return f"Detected ({selector})"
            except Exception:
                continue
        return "Unknown"

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes domain intelligence collection.

        Args:
            validation: EmailValidationResult dataclass.

        Returns:
            Structured dictionary with domain, DNS, security, and provider details.
        """
        domain = validation.domain

        # 1. Classify domain type
        domain_type = self.classify_domain_type(domain)

        # 2. DNS Lookups
        mx_records = self.resolve_mx(domain)
        txt_records = self.resolve_txt(domain)
        ns_records = self.resolve_ns(domain)
        a_records = self.resolve_a(domain)

        # 3. Security posture detection
        has_spf, spf_record = self.detect_spf(txt_records)
        has_dmarc, dmarc_record = self.detect_dmarc(domain)
        dkim_status = self.detect_dkim(domain)

        # 4. Mail provider & MX metrics
        has_mx = len(mx_records) > 0
        mx_count = len(mx_records)
        mail_provider = self.identify_mail_provider(domain, mx_records)

        # 5. Disposable domain status
        is_disposable = domain in DISPOSABLE_DOMAINS

        return {
            "collector": self.name,
            "status": "completed",
            "domain": domain,
            "domain_type": domain_type,
            "mail_provider": mail_provider,
            "has_mx": has_mx,
            "mx_count": mx_count,
            "mx_records": mx_records,
            "spf": has_spf,
            "spf_record": spf_record,
            "dmarc": has_dmarc,
            "dmarc_record": dmarc_record,
            "dkim": dkim_status,
            "disposable": is_disposable,
            "dns": {
                "mx": mx_records,
                "txt": txt_records,
                "ns": ns_records,
                "a": a_records,
            },
        }
