"""
============================================================
TraceLens Email Verification Collector
============================================================

Performs technical email verification including syntax check,
domain resolution, MX record lookup, provider classification,
disposable domain detection, SPF/DMARC posture detection,
custom domain SMTP mailbox verification & catch-all checking,
and evidence-based confidence score computation.

Author:
    TraceLens
"""

import logging
import random
import socket
import smtplib
import string
from typing import Any
import dns.resolver
import dns.exception

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import (
    EmailValidationResult,
    EmailValidator,
    PUBLIC_PROVIDERS,
    DISPOSABLE_DOMAINS,
)

logger = logging.getLogger(__name__)

# Major public providers that intentionally restrict mailbox enumeration
MAJOR_PUBLIC_PROVIDERS: dict[str, str] = {
    "gmail.com": "Gmail",
    "googlemail.com": "Gmail",
    "outlook.com": "Outlook",
    "hotmail.com": "Outlook",
    "live.com": "Outlook",
    "msn.com": "Outlook",
    "office365.com": "Outlook",
    "yahoo.com": "Yahoo",
    "ymail.com": "Yahoo",
    "rocketmail.com": "Yahoo",
    "proton.me": "Proton",
    "protonmail.com": "Proton",
    "pm.me": "Proton",
    "protonmail.ch": "Proton",
    "icloud.com": "iCloud",
    "me.com": "iCloud",
    "mac.com": "iCloud",
    "zoho.com": "Zoho",
    "zohomail.com": "Zoho",
    "zoho.eu": "Zoho",
    "zoho.in": "Zoho",
    "fastmail.com": "Fastmail",
    "fastmail.fm": "Fastmail",
    "messagingengine.com": "Fastmail",
    "aol.com": "AOL",
    "gmx.com": "GMX",
    "gmx.net": "GMX",
    "mail.com": "Mail.com",
    "yandex.com": "Yandex",
    "yandex.ru": "Yandex",
    "tuta.io": "Tuta",
    "tutamail.com": "Tuta",
    "tutanota.com": "Tutanota",
}


class VerificationCollector(BaseCollector):
    """
    Email Verification OSINT Collector.
    Executes a structured verification pipeline without claiming mailbox existence
    for public providers, and performs safe SMTP checks on custom domains.
    """

    def __init__(self, dns_timeout: float = 3.0, smtp_timeout: float = 4.0):
        super().__init__(name="Verification Collector", category="Verification")
        self.dns_timeout = dns_timeout
        self.smtp_timeout = smtp_timeout

    def _get_resolver(self) -> dns.resolver.Resolver:
        """Returns a configured DNS resolver with strict timeouts."""
        resolver = dns.resolver.Resolver()
        resolver.lifetime = self.dns_timeout
        resolver.timeout = self.dns_timeout
        return resolver

    def check_dns(self, domain: str) -> tuple[bool, list[dict[str, Any]], bool, bool]:
        """
        Performs DNS resolution for domain existence, MX, SPF, and DMARC.
        Returns (domain_exists, mx_records, has_spf, has_dmarc).
        """
        resolver = self._get_resolver()
        domain_exists = False
        mx_records: list[dict[str, Any]] = []
        has_spf = False
        has_dmarc = False

        # 1. Resolve MX records
        try:
            answers = resolver.resolve(domain, "MX")
            for rdata in answers:
                exchange_str = str(rdata.exchange).rstrip(".").lower()
                mx_records.append({
                    "exchange": exchange_str,
                    "preference": rdata.preference,
                })
            mx_records.sort(key=lambda x: x["preference"])
            domain_exists = True
            logger.info("[Verification] MX lookup successful for %s (%d records)", domain, len(mx_records))
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            logger.info("[Verification] MX lookup returned no records for %s", domain)
        except dns.resolver.NXDOMAIN:
            logger.info("[Verification] Domain %s does not exist (NXDOMAIN)", domain)
            return False, [], False, False
        except Exception as exc:
            logger.warning("[Verification] MX lookup error for %s: %s", domain, exc)

        # 2. Check A / AAAA / NS records if MX missed
        if not domain_exists:
            for record_type in ("A", "AAAA", "NS"):
                try:
                    res = resolver.resolve(domain, record_type)
                    if len(res) > 0:
                        domain_exists = True
                        logger.info("[Verification] Domain %s exists via %s record lookup", domain, record_type)
                        break
                except Exception:
                    continue

        if not domain_exists:
            logger.info("[Verification] Domain %s has no DNS records", domain)
            return False, [], False, False

        # 3. Check SPF (TXT records)
        try:
            txt_answers = resolver.resolve(domain, "TXT")
            for rdata in txt_answers:
                txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                if txt_str.startswith("v=spf1") or "v=spf1" in txt_str:
                    has_spf = True
                    break
        except Exception:
            pass

        # 4. Check DMARC
        try:
            dmarc_answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in dmarc_answers:
                txt_str = "".join([s.decode("utf-8", errors="ignore") for s in rdata.strings])
                if "v=DMARC1" in txt_str or txt_str.startswith("v=DMARC1"):
                    has_dmarc = True
                    break
        except Exception:
            pass

        return domain_exists, mx_records, has_spf, has_dmarc

    def check_custom_smtp(
        self, target_email: str, domain: str, mx_host: str
    ) -> tuple[bool, bool, str, str]:
        """
        Attempts SMTP verification and catch-all check on a custom domain MX host.
        Returns (smtp_supported, catch_all, mailbox_status, reason).
        """
        logger.info("[Verification] Attempting custom SMTP verification for %s via %s", target_email, mx_host)
        
        # Generate random dummy email to check catch-all behaviour
        rand_str = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        dummy_email = f"tl_catchall_{rand_str}@{domain}"

        try:
            smtp = smtplib.SMTP(timeout=self.smtp_timeout)
            smtp.connect(mx_host, 25)
            smtp.helo("tracelens-verify.net")
            
            # Send MAIL FROM
            mail_code, mail_resp = smtp.mail("verify@tracelens-verify.net")
            if mail_code != 250:
                smtp.quit()
                logger.info("[Verification] SMTP MAIL FROM rejected with code %d", mail_code)
                return False, False, "Unknown", "SMTP MAIL FROM command rejected by mail server."

            # Send RCPT TO for target email
            rcpt_code, rcpt_resp = smtp.rcpt(target_email)
            
            if rcpt_code == 250:
                # Mailbox accepted - check catch-all status with dummy address
                dummy_code, _ = smtp.rcpt(dummy_email)
                smtp.quit()

                if dummy_code == 250:
                    logger.info("[Verification] Catch-all domain detected for %s", domain)
                    return True, True, "Likely Exists", "Domain accepts all mail (Catch-all enabled)."
                else:
                    logger.info("[Verification] Mailbox verified for %s via SMTP", target_email)
                    return True, False, "Verified", "Mailbox confirmed active via SMTP verification."
            elif rcpt_code in (550, 551, 552, 553):
                smtp.quit()
                logger.info("[Verification] SMTP RCPT TO returned %d (Mailbox does not exist)", rcpt_code)
                return True, False, "Invalid", f"Mailbox rejected by mail server (SMTP code {rcpt_code})."
            else:
                smtp.quit()
                logger.info("[Verification] SMTP RCPT TO returned code %d", rcpt_code)
                return False, False, "Unknown", f"SMTP server returned inconclusive code {rcpt_code}."

        except (socket.timeout, TimeoutError):
            logger.info("[Verification] SMTP connection timed out for %s", mx_host)
            return False, False, "Unknown", "SMTP verification unavailable or timed out."
        except (socket.error, ConnectionRefusedError, smtplib.SMTPException) as exc:
            logger.info("[Verification] SMTP check failed for %s: %s", mx_host, exc)
            return False, False, "Unknown", "SMTP verification unavailable or blocked by server/network."
        except Exception as exc:
            logger.warning("[Verification] Unexpected SMTP error for %s: %s", mx_host, exc)
            return False, False, "Unknown", f"SMTP check encountered an error: {str(exc)}"

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes the Email Verification Pipeline.
        """
        email = validation.email
        domain = validation.domain
        local_part = validation.local_part

        logger.info("[Verification] Pipeline started for target: %s", email)

        # 1. Syntax Validation
        syntax_valid = validation.is_valid
        if syntax_valid:
            logger.info("[Verification] Syntax valid")
        else:
            logger.info("[Verification] Syntax invalid")
            return {
                "collector": self.name,
                "status": "completed",
                "syntax_valid": False,
                "domain_exists": False,
                "mx_present": False,
                "provider": "Unknown",
                "provider_type": "Unknown",
                "disposable": False,
                "smtp_supported": False,
                "catch_all": False,
                "mailbox_status": "Invalid",
                "confidence_score": 0,
                "reason": "Email syntax is invalid.",
            }

        # 2. Domain Extraction & DNS Lookups
        domain_exists, mx_records, has_spf, has_dmarc = self.check_dns(domain)
        mx_present = len(mx_records) > 0

        # 3. Detect Provider Type & Name
        is_public = False
        provider_name = validation.provider
        
        # Check if domain is in public provider lists
        domain_lower = domain.lower()
        if domain_lower in MAJOR_PUBLIC_PROVIDERS:
            is_public = True
            provider_short_name = MAJOR_PUBLIC_PROVIDERS[domain_lower]
            logger.info("[Verification] %s detected", provider_short_name)
        elif validation.provider_type == "public":
            is_public = True
            logger.info("[Verification] Public provider detected: %s", provider_name)
        else:
            logger.info("[Verification] Custom/Business domain detected for %s", domain)

        # 4. Detect Disposable Domain
        is_disposable = validation.is_disposable or (domain_lower in DISPOSABLE_DOMAINS)
        if is_disposable:
            logger.info("[Verification] Disposable domain detected for %s", domain)

        # 5. Handle Public vs Custom Domains for SMTP & Mailbox Status
        smtp_supported = False
        catch_all = False
        mailbox_status = "Unknown"
        reason = ""

        if not domain_exists:
            mailbox_status = "Invalid"
            reason = "Domain does not exist or has no DNS records."
        elif is_public:
            # Public providers intentionally block/prevent mailbox enumeration
            smtp_supported = False
            catch_all = False
            mailbox_status = "Unknown"
            provider_display = provider_name
            for p_domain, p_brand in MAJOR_PUBLIC_PROVIDERS.items():
                if p_domain in domain_lower:
                    provider_display = p_brand
                    break
            reason = f"Mailbox enumeration is disabled by {provider_display}."
            logger.info("[Verification] Mailbox enumeration unsupported for public provider %s", provider_display)
        elif not mx_present:
            smtp_supported = False
            mailbox_status = "Likely Invalid"
            reason = "Domain exists but has no MX mail exchanger records."
        else:
            # Custom domain with MX present - attempt SMTP verification safely
            primary_mx = mx_records[0]["exchange"]
            smtp_supported, catch_all, mailbox_status, reason = self.check_custom_smtp(
                email, domain, primary_mx
            )

        # 6. Generate Mailbox Confidence Score (0-100)
        confidence_score = 0
        if syntax_valid:
            confidence_score += 20
            logger.info("[Verification] +20 Syntax valid")

        if domain_exists:
            confidence_score += 20
            logger.info("[Verification] +20 Domain exists")

        if mx_present:
            confidence_score += 20
            logger.info("[Verification] +20 MX present")

        if has_spf:
            confidence_score += 10
            logger.info("[Verification] +10 SPF present")

        if has_dmarc:
            confidence_score += 10
            logger.info("[Verification] +10 DMARC present")

        if mailbox_status == "Verified" and smtp_supported:
            confidence_score += 20
            logger.info("[Verification] +20 Mailbox verified via SMTP")
        elif mailbox_status == "Likely Exists":
            confidence_score += 10
            logger.info("[Verification] +10 Mailbox likely exists")

        # Cap confidence score at 100, and ensure no public provider reaches 100 without SMTP verification
        confidence_score = min(100, max(0, confidence_score))
        logger.info("[Verification] Confidence = %d", confidence_score)

        provider_type_str = "Public" if is_public else "Custom / Business"

        return {
            "collector": self.name,
            "status": "completed",
            "syntax_valid": syntax_valid,
            "domain_exists": domain_exists,
            "mx_present": mx_present,
            "provider": provider_name,
            "provider_type": provider_type_str,
            "disposable": is_disposable,
            "smtp_supported": smtp_supported,
            "catch_all": catch_all,
            "mailbox_status": mailbox_status,
            "confidence_score": confidence_score,
            "reason": reason,
        }
