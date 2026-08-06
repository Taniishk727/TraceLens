"""
============================================================
TraceLens Phone Module & Parsing Collector Unit Tests
============================================================

Comprehensive tests for PhoneValidator, ParsingCollector, and PhoneEngine.
"""

import pytest
from app.osint.modules.phone.validator import PhoneValidator, InvalidPhoneError
from app.osint.modules.phone.collectors.parsing_collector import ParsingCollector
from app.osint.modules.phone.engine import PhoneEngine, investigate


@pytest.mark.parametrize(
    "raw_input, expected_e164, expected_country, expected_type",
    [
        ("+91 9876543210", "+919876543210", "India", "Mobile"),
        ("+1 415 555 2671", "+14155552671", "United States", "Fixed Line or Mobile"),
        ("9876543210", "+919876543210", "India", "Mobile"),
        ("(415) 555-2671", "+14155552671", "United States", "Fixed Line or Mobile"),
        ("+44 7400 123456", "+447400123456", "United Kingdom", "Mobile"),
    ],
)
def test_phone_validator_input_formats(raw_input, expected_e164, expected_country, expected_type):
    res = PhoneValidator.validate(raw_input, default_region="US" if "(" in raw_input else "IN")
    assert res.is_valid is True
    assert res.is_possible is True
    assert res.e164_format == expected_e164
    assert res.country_name == expected_country
    assert res.number_type in [expected_type, "Mobile", "Fixed Line or Mobile"]
    assert res.original_input == raw_input.strip()


def test_parsing_collector_result_object():
    validation = PhoneValidator.validate("+91 9876543210")
    collector = ParsingCollector()
    result = collector.collect(validation)

    assert result["success"] is True
    assert result["original"] == "+91 9876543210"
    assert result["normalized"] == "+919876543210"
    assert result["country"] == "India"
    assert result["country_code"] == "+91"
    assert result["national_number"] == "9876543210"
    assert result["type"] == "Mobile"
    assert result["valid"] is True
    assert result["possible"] is True
    assert "formats" in result
    assert result["formats"]["e164"] == "+919876543210"
    assert result["formats"]["international"] == "+91 98765 43210"
    assert "098765 43210" in result["formats"]["national"] or "98765" in result["formats"]["national"]


def test_phone_validator_empty_input():
    with pytest.raises(InvalidPhoneError):
        PhoneValidator.validate("")


def test_phone_validator_impossible_number():
    with pytest.raises(InvalidPhoneError):
        PhoneValidator.validate("123")


def test_phone_engine_investigate():
    res = investigate("+1 415 555 2671")
    assert res["success"] is True
    assert res["module"] == "Phone Investigation"
    assert res["target"] == "+14155552671"
    assert "parsed" in res
    assert "summary" in res
    assert "Valid" in res["summary"]
