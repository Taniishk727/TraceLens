"""
============================================================
TraceLens Milestone 3 Email OSINT Collectors Unit Tests
============================================================

Tests for ProviderCollector, GravatarCollector, PGPCollector, GitCollector,
BreachCollector, PublicSearchCollector, ReputationCollector, and EmailEngine orchestration.

Run:
    .\venv\Scripts\python.exe -m pytest tests/test_email_collectors_milestone3.py -v
"""

from unittest.mock import patch, MagicMock
import pytest

from app.osint.modules.email.validator import EmailValidator
from app.osint.modules.email.engine import EmailEngine, investigate
from app.osint.modules.email.collectors.provider import ProviderCollector
from app.osint.modules.email.collectors.gravatar import GravatarCollector
from app.osint.modules.email.collectors.pgp import PGPCollector
from app.osint.modules.email.collectors.github import GitCollector
from app.osint.modules.email.collectors.breach import BreachCollector
from app.osint.modules.email.collectors.public_search import PublicSearchCollector
from app.osint.modules.email.collectors.reputation import ReputationCollector


# ==========================================================
# PROVIDER COLLECTOR TESTS
# ==========================================================

def test_provider_collector_role_based_address():
    collector = ProviderCollector()
    
    # Test role-based emails
    val_admin = EmailValidator.validate("admin@company.com")
    res_admin = collector.collect(val_admin)
    assert res_admin["is_role_based"] is True
    assert res_admin["role_name"] == "Admin"

    val_support = EmailValidator.validate("tech-support@company.com")
    res_support = collector.collect(val_support)
    assert res_support["is_role_based"] is True

    # Test personal email
    val_personal = EmailValidator.validate("john.doe@company.com")
    res_personal = collector.collect(val_personal)
    assert res_personal["is_role_based"] is False
    assert res_personal["role_name"] is None


def test_provider_collector_domain_classification():
    collector = ProviderCollector()
    assert collector.classify_domain_type("gmail.com") == "Public"
    assert collector.classify_domain_type("stanford.edu") == "Educational"
    assert collector.classify_domain_type("usa.gov") == "Government"
    assert collector.classify_domain_type("acme-corp.io") == "Business / Custom"


# ==========================================================
# GRAVATAR COLLECTOR TESTS
# ==========================================================

def test_gravatar_collector_hash_and_missing():
    collector = GravatarCollector()
    val = EmailValidator.validate("nonexistent_user_123456789@example.com")
    md5_expected = "9e3798ae8276e39ce8cd115c7104eaac"
    assert collector.get_email_hash("nonexistent_user_123456789@example.com") == md5_expected

    with patch.object(collector, "fetch_gravatar_profile", return_value={}), \
         patch.object(collector, "check_avatar_exists", return_value=(False, "https://www.gravatar.com/avatar/test")):
        res = collector.collect(val)

    assert res["collector"] == "Gravatar Collector"
    assert res["status"] == "not_found"
    assert res["gravatar_exists"] is False
    assert res["display_name"] is None


def test_gravatar_collector_profile_found():
    collector = GravatarCollector()
    val = EmailValidator.validate("found_user@example.com")
    mock_entry = {
        "displayName": "Alex Dev",
        "profileUrl": "https://gravatar.com/alexdev",
        "aboutMe": "Security engineer & open-source contributor",
        "currentLocation": "New York, USA",
        "urls": [{"value": "https://alexdev.io"}],
    }

    with patch.object(collector, "fetch_gravatar_profile", return_value=mock_entry), \
         patch.object(collector, "check_avatar_exists", return_value=(True, "https://www.gravatar.com/avatar/hash")):
        res = collector.collect(val)

    assert res["status"] == "completed"
    assert res["gravatar_exists"] is True
    assert res["display_name"] == "Alex Dev"
    assert res["location"] == "New York, USA"
    assert "https://alexdev.io" in res["linked_websites"]


# ==========================================================
# PGP COLLECTOR TESTS
# ==========================================================

def test_pgp_collector_not_found():
    collector = PGPCollector()
    val = EmailValidator.validate("nobody@nonexistent-pgp-key.org")

    with patch.object(collector, "search_hkp_server", return_value=[]), \
         patch.object(collector, "search_keys_openpgp", return_value=[]):
        res = collector.collect(val)

    assert res["collector"] == "PGP Collector"
    assert res["status"] == "not_found"
    assert res["keys_found"] == 0
    assert res["keys"] == []


def test_pgp_collector_found():
    collector = PGPCollector()
    val = EmailValidator.validate("sec@pgp-domain.com")
    mock_key = {
        "key_id": "0x4A7C9B10",
        "fingerprint": "1234567890ABCDEF",
        "created_date": "2024-01-01",
        "expiry_date": "Never",
        "user_ids": ["sec@pgp-domain.com"],
        "email_matches": ["sec@pgp-domain.com"],
    }

    with patch.object(collector, "search_hkp_server", return_value=[mock_key]):
        res = collector.collect(val)

    assert res["status"] == "completed"
    assert res["keys_found"] == 1
    assert res["keys"][0]["key_id"] == "0x4A7C9B10"


# ==========================================================
# PUBLIC GIT COLLECTOR TESTS
# ==========================================================

def test_git_collector_found():
    collector = GitCollector()
    val = EmailValidator.validate("developer@github-user.org")

    with patch.object(collector, "search_github_users", return_value={"login": "devuser", "html_url": "https://github.com/devuser"}), \
         patch.object(collector, "search_github_commits", return_value={"total_count": 5, "items": [{"commit": {"author": {"name": "Dev User"}}, "repository": {"full_name": "org/repo1", "owner": {"login": "org"}}}]}):
        res = collector.collect(val)

    assert res["status"] == "completed"
    assert res["commit_count"] == 5
    assert "org/repo1" in res["repositories"]
    assert res["public_profile"] == "https://github.com/devuser"


def test_git_collector_rate_limited():
    collector = GitCollector()
    val = EmailValidator.validate("dev@rate-limit.org")

    with patch.object(collector, "search_github_users", return_value={"rate_limited": True}), \
         patch.object(collector, "search_github_commits", return_value={"rate_limited": True}):
        res = collector.collect(val)

    assert res["status"] == "unavailable"
    assert "rate limit" in res["reason"].lower()


# ==========================================================
# BREACH COLLECTOR TESTS
# ==========================================================

def test_breach_collector_unconfigured_api_key():
    collector = BreachCollector()
    collector.hibp_api_key = None
    val = EmailValidator.validate("user@example.com")
    res = collector.collect(val)

    assert res["status"] == "unavailable"
    assert res["pwned_status"] is None
    assert res["breaches_found"] == 0
    assert "HIBP_API_KEY required" in res["reason"]


def test_breach_collector_configured_api_key_found():
    collector = BreachCollector()
    collector.hibp_api_key = "test_key_123"
    val = EmailValidator.validate("pwned_user@example.com")

    mock_hibp_resp = {
        "pwned": True,
        "breaches_found": 2,
        "breach_sources": ["Adobe", "LinkedIn"],
    }

    with patch.object(collector, "query_hibp", return_value=mock_hibp_resp):
        res = collector.collect(val)

    assert res["status"] == "completed"
    assert res["pwned_status"] is True
    assert res["breaches_found"] == 2
    assert "Adobe" in res["breach_sources"]


# ==========================================================
# REPUTATION COLLECTOR TESTS
# ==========================================================

def test_reputation_collector_scoring():
    collector = ReputationCollector()
    
    # Personal corporate email
    val_corp = EmailValidator.validate("john@techcorp.com")
    res_corp = collector.collect(val_corp)
    assert res_corp["reputation_score"] > 70
    assert res_corp["is_disposable"] is False

    # Disposable email
    val_disp = EmailValidator.validate("temp@tempmail.com")
    res_disp = collector.collect(val_disp)
    assert res_disp["reputation_score"] < 50
    assert res_disp["is_disposable"] is True


# ==========================================================
# ENGINE INTEGRATION & TIMING TESTS
# ==========================================================

def test_email_engine_milestone3_orchestration():
    """Verify EmailEngine runs registered collectors concurrently and reports execution times."""
    res = investigate("admin@google.com")
    assert res["success"] is True
    assert res["summary"]["total_collectors"] == 11
    assert len(res["results"]) == 11

    for col in res["results"]:
        assert "collector" in col
        assert "status" in col
        assert "execution_time_ms" in col
        assert isinstance(col["execution_time_ms"], (int, float))

    # Verify summary section contains Milestone 3 fields
    summary = res["summary"]
    assert "normalized_email" in summary
    assert "mailbox_status" in summary
    assert "confidence_score" in summary
    assert "is_role_based" in summary
    assert summary["is_role_based"] is True
    assert summary["role_name"] == "Admin"
