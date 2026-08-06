"""
============================================================
TraceLens Verification Collector Unit Tests
============================================================

Tests for VerificationCollector handling public providers,
custom domains, DNS failures, SMTP verification, catch-all detection,
confidence scoring, and EmailEngine integration.

Run:
    .\venv\Scripts\python.exe -m pytest tests/test_verification_collector.py -v
"""

from unittest.mock import patch, MagicMock
import socket
import smtplib
import pytest

from app.osint.modules.email.validator import EmailValidator
from app.osint.modules.email.collectors.verification import VerificationCollector
from app.osint.modules.email.engine import EmailEngine, investigate


def test_public_provider_gmail_unknown_enumeration():
    """Public providers (Gmail) must always return Mailbox Status: Unknown with explicit reason."""
    collector = VerificationCollector()
    validation = EmailValidator.validate("test.user@gmail.com")
    
    # Mock DNS lookup for gmail.com to avoid network dependency in unit test
    with patch.object(collector, "check_dns") as mock_dns:
        mock_dns.return_value = (True, [{"exchange": "gmail-smtp-in.l.google.com", "preference": 5}], True, True)
        result = collector.collect(validation)

    assert result["collector"] == "Verification Collector"
    assert result["syntax_valid"] is True
    assert result["domain_exists"] is True
    assert result["mx_present"] is True
    assert result["provider"] == "Google Workspace / Gmail"
    assert result["provider_type"] == "Public"
    assert result["smtp_supported"] is False
    assert result["catch_all"] is False
    assert result["mailbox_status"] == "Unknown"
    assert "disabled by Gmail" in result["reason"] or "disabled by" in result["reason"]
    assert result["confidence_score"] == 80  # 20 syntax + 20 domain + 20 MX + 10 SPF + 10 DMARC


def test_public_providers_outlook_proton_icloud():
    """Verify that Outlook, Proton, iCloud, Yahoo, Zoho, Fastmail also return Unknown mailbox status."""
    providers_test = [
        ("john@outlook.com", "Microsoft Outlook"),
        ("user@proton.me", "Proton Mail"),
        ("alice@icloud.com", "Apple iCloud"),
        ("test@yahoo.com", "Yahoo Mail"),
        ("sales@zoho.com", "Zoho Mail"),
        ("user@fastmail.com", "Fastmail"),
    ]
    collector = VerificationCollector()

    for email_str, expected_provider_name in providers_test:
        validation = EmailValidator.validate(email_str)
        with patch.object(collector, "check_dns") as mock_dns:
            mock_dns.return_value = (True, [{"exchange": "mail.example.com", "preference": 10}], True, True)
            res = collector.collect(validation)
        
        assert res["mailbox_status"] == "Unknown"
        assert res["smtp_supported"] is False
        assert "disabled by" in res["reason"]


def test_nonexistent_domain_invalid():
    """Non-existent domain (NXDOMAIN) returns Mailbox Status: Invalid."""
    collector = VerificationCollector()
    validation = EmailValidator.validate("target@nonexistent-domain-123456789.org")
    
    with patch.object(collector, "check_dns") as mock_dns:
        mock_dns.return_value = (False, [], False, False)
        res = collector.collect(validation)

    assert res["domain_exists"] is False
    assert res["mx_present"] is False
    assert res["mailbox_status"] == "Invalid"
    assert res["confidence_score"] == 20  # Syntax valid (+20) only
    assert "does not exist" in res["reason"]


def test_custom_domain_smtp_verified():
    """Custom domain with successful SMTP verification returns Mailbox Status: Verified with 100 confidence."""
    collector = VerificationCollector()
    validation = EmailValidator.validate("admin@customcompany.org")

    with patch.object(collector, "check_dns") as mock_dns, \
         patch.object(collector, "check_custom_smtp") as mock_smtp:
        mock_dns.return_value = (True, [{"exchange": "mail.customcompany.org", "preference": 10}], True, True)
        mock_smtp.return_value = (True, False, "Verified", "Mailbox confirmed active via SMTP verification.")

        res = collector.collect(validation)

    assert res["provider_type"] == "Custom / Business"
    assert res["smtp_supported"] is True
    assert res["catch_all"] is False
    assert res["mailbox_status"] == "Verified"
    assert res["confidence_score"] == 100  # 20 + 20 + 20 + 10 + 10 + 20 = 100


def test_custom_domain_catch_all_detection():
    """Custom domain catch-all detection returns Mailbox Status: Likely Exists."""
    collector = VerificationCollector()
    validation = EmailValidator.validate("user@catchall-company.com")

    with patch.object(collector, "check_dns") as mock_dns, \
         patch.object(collector, "check_custom_smtp") as mock_smtp:
        mock_dns.return_value = (True, [{"exchange": "mail.catchall-company.com", "preference": 10}], True, True)
        mock_smtp.return_value = (True, True, "Likely Exists", "Domain accepts all mail (Catch-all enabled).")

        res = collector.collect(validation)

    assert res["catch_all"] is True
    assert res["mailbox_status"] == "Likely Exists"
    assert res["confidence_score"] == 90  # 80 base + 10 likely exists


def test_custom_domain_smtp_blocked_timeout():
    """Custom domain where SMTP port 25 is blocked or times out returns Mailbox Status: Unknown."""
    collector = VerificationCollector()
    validation = EmailValidator.validate("info@blocked-server.net")

    with patch.object(collector, "check_dns") as mock_dns, \
         patch.object(collector, "check_custom_smtp") as mock_smtp:
        mock_dns.return_value = (True, [{"exchange": "mx.blocked-server.net", "preference": 10}], True, False)
        mock_smtp.return_value = (False, False, "Unknown", "SMTP verification unavailable or timed out.")

        res = collector.collect(validation)

    assert res["smtp_supported"] is False
    assert res["mailbox_status"] == "Unknown"
    assert res["confidence_score"] == 70  # 20 + 20 + 20 + 10 (SPF)


def test_engine_investigate_includes_verification_collector():
    """Verify EmailEngine registers and runs Verification Collector."""
    res = investigate("security@gmail.com")
    assert res["success"] is True
    collector_names = [r["collector"] for r in res["results"]]
    assert "Verification Collector" in collector_names
    
    verif_res = next(r for r in res["results"] if r["collector"] == "Verification Collector")
    assert verif_res["syntax_valid"] is True
    assert "mailbox_status" in verif_res
    assert "confidence_score" in verif_res
