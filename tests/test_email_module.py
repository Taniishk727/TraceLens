"""
============================================================
TraceLens Email Module Unit Tests
============================================================

Tests for EmailValidator, EmailEngine, BaseCollector, and placeholder collectors.

Run:
    pytest tests/test_email_module.py -v
"""

import pytest

from app.osint.modules.email.validator import (
    EmailValidator,
    EmailValidationResult,
    InvalidEmailError,
)
from app.osint.modules.email.engine import (
    EmailEngine,
    BaseCollector,
    investigate,
)


# ==========================================================
# VALIDATOR TESTS
# ==========================================================

def test_email_validator_gmail_public():
    res = EmailValidator.validate("  User.Name+tag@Gmail.COM  ")
    assert isinstance(res, EmailValidationResult)
    assert res.email == "user.name+tag@gmail.com"
    assert res.local_part == "user.name+tag"
    assert res.domain == "gmail.com"
    assert res.is_valid is True
    assert res.provider == "Google Workspace / Gmail"
    assert res.provider_type == "public"
    assert res.is_disposable is False


def test_email_validator_custom_business():
    res = EmailValidator.validate("security@company.org")
    assert res.email == "security@company.org"
    assert res.local_part == "security"
    assert res.domain == "company.org"
    assert res.provider == "Custom (company.org)"
    assert res.provider_type == "business"
    assert res.is_disposable is False


def test_email_validator_disposable():
    res = EmailValidator.validate("temp_user@tempmail.com")
    assert res.domain == "tempmail.com"
    assert res.is_disposable is True


def test_email_validator_invalid_syntax():
    invalid_emails = [
        "",
        "   ",
        "invalid_email",
        "@domain.com",
        "user@",
        "user@domain",
        12345,
    ]
    for email_input in invalid_emails:
        with pytest.raises(InvalidEmailError):
            EmailValidator.validate(email_input)


# ==========================================================
# ENGINE TESTS
# ==========================================================

def test_email_engine_investigate_valid():
    res = investigate("john_doe@proton.me")
    assert res["success"] is True
    assert res["module"] == "Email Investigation"
    assert res["status"] == "completed"
    assert res["target"] == "john_doe@proton.me"
    assert res["parsed"]["provider"] == "Proton Mail"
    assert res["parsed"]["provider_type"] == "public"
    assert len(res["results"]) == 11


def test_email_engine_investigate_invalid():
    res = investigate("invalid-email-address")
    assert res["success"] is False
    assert res["module"] == "Email"
    assert res["target"] == "invalid-email-address"
    assert "error" in res


# ==========================================================
# CUSTOM COLLECTOR REGISTRATION TEST
# ==========================================================

class DummyTestCollector(BaseCollector):
    def __init__(self):
        super().__init__(name="Dummy Collector", category="Test")

    def collect(self, validation: EmailValidationResult) -> dict:
        return {
            "collector": self.name,
            "status": "success",
            "dummy_key": f"value_for_{validation.local_part}",
        }


def test_custom_collector_registration():
    engine = EmailEngine()
    engine.register_collector(DummyTestCollector())
    res = engine.investigate("tester@customdomain.io")
    assert res["success"] is True
    collector_names = [r["collector"] for r in res["results"]]
    assert "Dummy Collector" in collector_names
