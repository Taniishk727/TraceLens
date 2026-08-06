"""
============================================================
TraceLens Breach Provider Unit Tests
============================================================

Covers the full provider abstraction layer:
    - BreachRecord and ProviderResult data models
    - HIBPProvider: unconfigured, configured, HTTP 200, 404, 401, 429, timeout
    - BreachCollector: provider delegation, unavailable cascade, legacy compat

Run:
    .\\venv\\Scripts\\python.exe -m pytest tests/test_breach_providers.py -v
"""

from unittest.mock import MagicMock, patch
import urllib.error
import pytest

from app.osint.modules.email.providers.breach.base import (
    BaseBreachProvider,
    BreachRecord,
    ProviderResult,
)
from app.osint.modules.email.providers.breach.hibp import HIBPProvider
from app.osint.modules.email.providers.breach.leakcheck import LeakCheckProvider
from app.osint.modules.email.providers.breach.hudsonrock import HudsonRockProvider
from app.osint.modules.email.collectors.breach import BreachCollector
from app.osint.modules.email.validator import EmailValidator


# ==========================================================
# DATA MODEL TESTS
# ==========================================================


def test_breach_record_defaults():
    """BreachRecord populates all fields and defaults correctly."""
    record = BreachRecord(
        name="TestBreach",
        domain="test.com",
        breach_date="2022-01-15",
        added_date="2022-03-01",
        description="A test breach.",
        data_classes=["Email addresses", "Passwords"],
    )
    assert record.name == "TestBreach"
    assert record.domain == "test.com"
    assert record.breach_date == "2022-01-15"
    assert record.added_date == "2022-03-01"
    assert record.verified is True        # default
    assert record.sensitive is False      # default
    assert record.retired is False        # default
    assert record.spam_list is False      # default
    assert "Email addresses" in record.data_classes


def test_breach_record_to_dict():
    """BreachRecord.to_dict() returns the correct plain dictionary."""
    record = BreachRecord(
        name="Acme",
        domain="acme.com",
        breach_date="2020-05-10",
        added_date="2020-07-01",
        description="Acme breach.",
        data_classes=["Passwords"],
        verified=False,
        sensitive=True,
    )
    d = record.to_dict()
    assert d["name"] == "Acme"
    assert d["domain"] == "acme.com"
    assert d["verified"] is False
    assert d["sensitive"] is True
    assert d["data_classes"] == ["Passwords"]


def test_provider_result_defaults():
    """ProviderResult initialises with sensible defaults."""
    result = ProviderResult(provider_name="HIBP", available=True)
    assert result.email_found is False
    assert result.total_breaches == 0
    assert result.total_data_categories == 0
    assert result.breaches == []
    assert result.error_message is None


def test_provider_result_to_dict():
    """ProviderResult.to_dict() serialises nested BreachRecord objects."""
    breach = BreachRecord(
        name="LinkedIn",
        domain="linkedin.com",
        breach_date="2012-05-05",
        added_date="2016-05-22",
        description="LinkedIn breach.",
        data_classes=["Email addresses", "Passwords"],
    )
    result = ProviderResult(
        provider_name="HIBP",
        available=True,
        email_found=True,
        total_breaches=1,
        total_data_categories=2,
        breaches=[breach],
    )
    d = result.to_dict()
    assert d["provider_name"] == "HIBP"
    assert d["available"] is True
    assert d["email_found"] is True
    assert d["total_breaches"] == 1
    assert d["total_data_categories"] == 2
    assert len(d["breaches"]) == 1
    assert d["breaches"][0]["name"] == "LinkedIn"


# ==========================================================
# HIBP PROVIDER TESTS
# ==========================================================


def test_hibp_provider_no_api_key():
    """HIBPProvider returns available=False immediately when no API key is set."""
    provider = HIBPProvider(api_key=None)
    provider.api_key = None  # Ensure no env var leaked in
    result = provider.search("user@example.com")

    assert result.available is False
    assert result.email_found is False
    assert result.total_breaches == 0
    assert "API key not configured" in (result.error_message or "")


def test_hibp_provider_email_not_found_404():
    """HIBPProvider returns available=True, email_found=False on 404."""
    provider = HIBPProvider(api_key="fake_key_for_test")

    # Simulate 404 HTTP response
    http_error = urllib.error.HTTPError(
        url="https://haveibeenpwned.com/api/v3/breachedaccount/clean%40example.com",
        code=404,
        msg="Not Found",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,    # type: ignore[arg-type]
    )

    with patch("urllib.request.urlopen", side_effect=http_error):
        result = provider.search("clean@example.com")

    assert result.available is True
    assert result.email_found is False
    assert result.total_breaches == 0
    assert result.breaches == []


def test_hibp_provider_successful_response():
    """HIBPProvider normalises a full HIBP JSON response into BreachRecords."""
    provider = HIBPProvider(api_key="fake_key_for_test")

    fake_response = [
        {
            "Name": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04T00:00:00Z",
            "Description": "Adobe breach description.",
            "DataClasses": ["Email addresses", "Passwords", "Usernames"],
            "IsVerified": True,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
        },
        {
            "Name": "LinkedIn",
            "Domain": "linkedin.com",
            "BreachDate": "2012-05-05",
            "AddedDate": "2016-05-22T00:00:00Z",
            "Description": "LinkedIn breach description.",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "IsSensitive": False,
            "IsRetired": False,
            "IsSpamList": False,
        },
    ]

    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.status = 200
    mock_resp.read.return_value = __import__("json").dumps(fake_response).encode("utf-8")

    with patch("urllib.request.urlopen", return_value=mock_resp):
        result = provider.search("pwned@example.com")

    assert result.available is True
    assert result.email_found is True
    assert result.total_breaches == 2
    assert result.total_data_categories == 3   # Email addresses, Passwords, Usernames
    assert result.breaches[0].name == "Adobe"
    assert result.breaches[0].breach_date == "2013-10-04"
    assert result.breaches[0].added_date == "2013-12-04"   # Truncated to date
    assert result.breaches[1].name == "LinkedIn"
    assert "Passwords" in result.breaches[0].data_classes


def test_hibp_provider_401_unauthorized():
    """HIBPProvider returns available=False on 401."""
    provider = HIBPProvider(api_key="bad_key")

    http_error = urllib.error.HTTPError(
        url="https://haveibeenpwned.com/api/v3/breachedaccount/user%40example.com",
        code=401,
        msg="Unauthorized",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,    # type: ignore[arg-type]
    )

    with patch("urllib.request.urlopen", side_effect=http_error):
        result = provider.search("user@example.com")

    assert result.available is False


def test_hibp_provider_429_rate_limited():
    """HIBPProvider returns available=False on 429 rate limit."""
    provider = HIBPProvider(api_key="real_key")

    http_error = urllib.error.HTTPError(
        url="https://haveibeenpwned.com/api/v3/breachedaccount/user%40example.com",
        code=429,
        msg="Too Many Requests",
        hdrs=None,  # type: ignore[arg-type]
        fp=None,    # type: ignore[arg-type]
    )

    with patch("urllib.request.urlopen", side_effect=http_error):
        result = provider.search("user@example.com")

    assert result.available is False


def test_hibp_provider_timeout():
    """HIBPProvider returns available=False on timeout."""
    provider = HIBPProvider(api_key="real_key", timeout=1.0)

    with patch("urllib.request.urlopen", side_effect=TimeoutError("timed out")):
        result = provider.search("user@example.com")

    assert result.available is False


def test_hibp_normalise_breach_field_mapping():
    """_normalise_breach correctly maps all HIBP fields."""
    raw = {
        "Name": "HackedSite",
        "Domain": "hackedsite.com",
        "BreachDate": "2021-03-15",
        "AddedDate": "2021-06-01T12:00:00Z",
        "Description": "Sensitive content stolen.",
        "DataClasses": ["Credit cards", "Email addresses"],
        "IsVerified": False,
        "IsSensitive": True,
        "IsRetired": True,
        "IsSpamList": True,
    }
    record = HIBPProvider._normalise_breach(raw)
    assert record.name == "HackedSite"
    assert record.domain == "hackedsite.com"
    assert record.breach_date == "2021-03-15"
    assert record.added_date == "2021-06-01"   # Truncated
    assert record.verified is False
    assert record.sensitive is True
    assert record.retired is True
    assert record.spam_list is True


# ==========================================================
# STUB PROVIDER TESTS
# ==========================================================


def test_leakcheck_provider_stub_unavailable():
    """LeakCheckProvider stub always returns unavailable."""
    provider = LeakCheckProvider()
    result = provider.search("user@example.com")
    assert result.available is False
    assert result.provider_name == "LeakCheck"


def test_hudsonrock_provider_stub_unavailable():
    """HudsonRockProvider stub always returns unavailable."""
    provider = HudsonRockProvider()
    result = provider.search("user@example.com")
    assert result.available is False
    assert result.provider_name == "HudsonRock"


# ==========================================================
# BREACH COLLECTOR INTEGRATION TESTS
# ==========================================================


def test_breach_collector_no_api_key_returns_unavailable():
    """BreachCollector returns status=unavailable when no provider has a key."""
    collector = BreachCollector()
    collector.hibp_api_key = None

    val = EmailValidator.validate("user@example.com")
    result = collector.collect(val)

    assert result["status"] == "unavailable"
    assert result["provider_available"] is False
    assert result["email_found"] is False
    assert result["total_breaches"] == 0
    assert result["total_data_categories"] == 0
    assert result["breaches"] == []
    # Legacy compat
    assert result["pwned_status"] is None
    assert result["breaches_found"] == 0
    assert result["breach_sources"] == []
    assert "HIBP_API_KEY required" in result["reason"]


def test_breach_collector_with_key_clean_email():
    """BreachCollector returns status=not_found when email has no breaches."""
    collector = BreachCollector()
    collector.hibp_api_key = "test_key"

    # Patch query_hibp — the patchable entry-point that collect() calls.
    # No '_provider_result' key → triggers the mocked-path fallback.
    clean_raw = {
        "pwned": False,
        "breaches_found": 0,
        "breach_sources": [],
    }

    val = EmailValidator.validate("clean@example.com")

    with patch.object(collector, "query_hibp", return_value=clean_raw):
        result = collector.collect(val)

    assert result["status"] == "not_found"
    assert result["email_found"] is False
    assert result["total_breaches"] == 0
    assert result["provider"] == "HIBP"
    # Legacy compat
    assert result["pwned_status"] is False
    assert result["breach_sources"] == []


def test_breach_collector_with_key_pwned_email():
    """BreachCollector returns full normalized data when email is found via rich ProviderResult."""
    collector = BreachCollector()
    collector.hibp_api_key = "test_key"

    adobe_breach = BreachRecord(
        name="Adobe",
        domain="adobe.com",
        breach_date="2013-10-04",
        added_date="2013-12-04",
        description="Adobe breach.",
        data_classes=["Email addresses", "Passwords", "Usernames"],
        verified=True,
        sensitive=False,
    )
    linkedin_breach = BreachRecord(
        name="LinkedIn",
        domain="linkedin.com",
        breach_date="2012-05-05",
        added_date="2016-05-22",
        description="LinkedIn breach.",
        data_classes=["Email addresses", "Passwords"],
        verified=True,
        sensitive=False,
    )

    pwned_result = ProviderResult(
        provider_name="HIBP",
        available=True,
        email_found=True,
        total_breaches=2,
        total_data_categories=3,
        breaches=[adobe_breach, linkedin_breach],
    )

    # Patch query_hibp WITH _provider_result to exercise the rich data path.
    pwned_raw = {
        "pwned": True,
        "breaches_found": 2,
        "breach_sources": ["Adobe", "LinkedIn"],
        "_provider_result": pwned_result,
    }

    val = EmailValidator.validate("pwned@example.com")

    with patch.object(collector, "query_hibp", return_value=pwned_raw):
        result = collector.collect(val)

    assert result["status"] == "completed"
    assert result["provider"] == "HIBP"
    assert result["provider_available"] is True
    assert result["email_found"] is True
    assert result["total_breaches"] == 2
    assert result["total_data_categories"] == 3
    assert len(result["breaches"]) == 2
    assert result["breaches"][0]["name"] == "Adobe"
    assert result["breaches"][0]["breach_date"] == "2013-10-04"
    assert "Passwords" in result["breaches"][0]["data_classes"]
    # Legacy compat fields
    assert result["pwned_status"] is True
    assert result["breaches_found"] == 2
    assert "Adobe" in result["breach_sources"]
    assert "LinkedIn" in result["breach_sources"]


def test_breach_collector_legacy_query_hibp_no_key():
    """query_hibp() returns None when no API key is set (legacy compat)."""
    collector = BreachCollector()
    collector.hibp_api_key = None
    result = collector.query_hibp("user@example.com")
    assert result is None


def test_breach_collector_legacy_query_hibp_with_key():
    """query_hibp() returns legacy dict shape when provider responds."""
    collector = BreachCollector()
    collector.hibp_api_key = "test_key"

    provider_res = ProviderResult(
        provider_name="HIBP",
        available=True,
        email_found=True,
        total_breaches=1,
        breaches=[
            BreachRecord(
                name="MyFitnessPal",
                domain="myfitnesspal.com",
                breach_date="2018-02-01",
                added_date="2018-03-29",
                description="MFP breach.",
                data_classes=["Email addresses", "Passwords"],
            )
        ],
    )

    with patch.object(HIBPProvider, "search", return_value=provider_res):
        result = collector.query_hibp("user@example.com")

    assert result is not None
    assert result["pwned"] is True
    assert result["breaches_found"] == 1
    assert "MyFitnessPal" in result["breach_sources"]


def test_breach_collector_all_providers_unavailable_cascades():
    """BreachCollector returns unavailable if HIBP returns None and stubs are unavailable."""
    collector = BreachCollector()
    collector.hibp_api_key = "some_key"

    val = EmailValidator.validate("user@example.com")

    # query_hibp returns None → HIBP unavailable (bad key / network error)
    with patch.object(collector, "query_hibp", return_value=None):
        result = collector.collect(val)

    # LeakCheck and HudsonRock stubs are both unavailable, so result is unavailable
    assert result["status"] == "unavailable"
    assert result["provider_available"] is False
