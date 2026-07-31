"""
============================================================
TraceLens Domain Collector Unit Tests
============================================================

Tests for DomainCollector classification, DNS lookups, security posture
(SPF, DMARC, DKIM), provider detection, and exception handling.

Run:
    pytest tests/test_domain_collector.py -v
"""

from unittest.mock import Mock, patch
import pytest

from app.osint.modules.email.validator import EmailValidator
from app.osint.modules.email.collectors.domain_collector import DomainCollector
from app.osint.modules.email.engine import investigate


def test_domain_collector_classification():
    collector = DomainCollector()
    assert collector.classify_domain_type("gmail.com") == "Public"
    assert collector.classify_domain_type("harvard.edu") == "Educational"
    assert collector.classify_domain_type("oxford.ac.uk") == "Educational"
    assert collector.classify_domain_type("whitehouse.gov") == "Government"
    assert collector.classify_domain_type("custombrand.com") == "Business / Custom"


def test_domain_collector_mail_provider_identification():
    collector = DomainCollector()
    google_mx = [{"exchange": "aspmx.l.google.com", "preference": 1}]
    ms_mx = [{"exchange": "company-org.mail.protection.outlook.com", "preference": 10}]
    zoho_mx = [{"exchange": "mx.zoho.com", "preference": 10}]
    unknown_mx = [{"exchange": "mail.customserver.net", "preference": 10}]

    assert collector.identify_mail_provider("company.com", google_mx) == "Google Workspace"
    assert collector.identify_mail_provider("company.com", ms_mx) == "Microsoft 365 / Exchange"
    assert collector.identify_mail_provider("company.com", zoho_mx) == "Zoho Mail"
    assert "Custom / Self-Hosted" in collector.identify_mail_provider("company.com", unknown_mx)
    assert collector.identify_mail_provider("company.com", []) == "None (No MX Records)"


def test_domain_collector_spf_dmarc_detection():
    collector = DomainCollector()
    txt_records = [
        "v=spf1 include:_spf.google.com ~all",
        "google-site-verification=xyz123",
    ]
    has_spf, spf_rec = collector.detect_spf(txt_records)
    assert has_spf is True
    assert "v=spf1" in spf_rec

    has_spf_missing, spf_rec_missing = collector.detect_spf(["google-site-verification=abc"])
    assert has_spf_missing is False
    assert spf_rec_missing is None


@patch("dns.resolver.Resolver.resolve")
def test_domain_collector_collect_success(mock_resolve):
    # Mock DNS answers
    def mock_dns_query(domain, rtype, **kwargs):
        mock_ans = Mock()
        if rtype == "MX":
            r1 = Mock()
            r1.exchange = "aspmx.l.google.com."
            r1.preference = 5
            mock_ans.__iter__ = Mock(return_value=iter([r1]))
            return mock_ans
        elif rtype == "TXT":
            r1 = Mock()
            r1.strings = [b"v=spf1 redirect=_spf.google.com"]
            mock_ans.__iter__ = Mock(return_value=iter([r1]))
            return mock_ans
        elif rtype == "NS":
            r1 = Mock()
            r1.target = "ns1.google.com."
            mock_ans.__iter__ = Mock(return_value=iter([r1]))
            return mock_ans
        elif rtype == "A":
            r1 = Mock()
            r1.address = "142.250.190.46"
            mock_ans.__iter__ = Mock(return_value=iter([r1]))
            return mock_ans
        raise Exception("DNS Query Failed")

    mock_resolve.side_effect = mock_dns_query

    collector = DomainCollector()
    val_res = EmailValidator.validate("test@gmail.com")
    res = collector.collect(val_res)

    assert res["collector"] == "Domain Collector"
    assert res["status"] == "completed"
    assert res["domain"] == "gmail.com"
    assert res["domain_type"] == "Public"
    assert res["mail_provider"] == "Google Workspace"
    assert res["has_mx"] is True
    assert res["mx_count"] == 1
    assert res["spf"] is True
    assert res["dns"]["mx"][0]["exchange"] == "aspmx.l.google.com"


@patch("dns.resolver.Resolver.resolve")
def test_domain_collector_dns_failure_graceful_handling(mock_resolve):
    mock_resolve.side_effect = Exception("DNS Resolution Timeout / Failure")

    collector = DomainCollector()
    val_res = EmailValidator.validate("user@nonexistentdomain12345.org")
    res = collector.collect(val_res)

    assert res["collector"] == "Domain Collector"
    assert res["status"] == "completed"
    assert res["has_mx"] is False
    assert res["mx_count"] == 0
    assert res["spf"] is False
    assert res["dmarc"] is False
    assert res["dkim"] == "Unknown"
