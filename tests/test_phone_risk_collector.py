"""
============================================================
TraceLens Phone Risk Collector Unit Tests
============================================================

Tests for rule-based risk evaluation, indicator formatting,
public exposure scoring, and engine integration.
"""

from unittest.mock import MagicMock
import pytest

from app.osint.modules.phone.validator import PhoneValidator
from app.osint.modules.phone.collectors.risk.rules import (
    evaluate_risk_rules,
    classify_risk_level,
)
from app.osint.modules.phone.collectors.risk.collector import RiskCollector
from app.osint.modules.phone.engine import PhoneEngine, investigate


def test_classify_risk_level():
    assert classify_risk_level(0) == "LOW"
    assert classify_risk_level(15) == "LOW"
    assert classify_risk_level(29) == "LOW"
    assert classify_risk_level(30) == "MEDIUM"
    assert classify_risk_level(45) == "MEDIUM"
    assert classify_risk_level(59) == "MEDIUM"
    assert classify_risk_level(60) == "HIGH"
    assert classify_risk_level(85) == "HIGH"
    assert classify_risk_level(100) == "HIGH"


def test_risk_rules_valid_mobile_low_risk():
    validation = PhoneValidator.validate("+91 9876543210")
    carrier_res = {
        "collector": "Carrier Intelligence Collector",
        "carrier": "Airtel",
        "network": "Mobile Network",
    }
    public_search_res = {
        "collector": "Public Search Collector",
        "total_results": 3,
        "unique_domains_count": 2,
    }

    res = evaluate_risk_rules(validation, carrier_res=carrier_res, public_search_res=public_search_res)

    assert res["score"] == 0
    assert res["level"] == "LOW"
    assert "Valid Number" in res["positive_findings"]
    assert "Carrier Identified" in res["positive_findings"]
    assert len(res["risk_findings"]) == 0
    assert res["public_exposure"]["level"] == "LOW"
    assert res["public_exposure"]["references"] == 3
    assert res["public_exposure"]["unique_domains"] == 2
    assert "No significant risk indicators detected" in res["summary"]

    # Visual symbols check
    symbols = [ind["symbol"] for ind in res["indicators"]]
    assert "✓" in symbols


def test_risk_rules_premium_rate_high_risk():
    validation = MagicMock()
    validation.is_valid = True
    validation.is_possible = True
    validation.number_type = "Premium Rate"
    validation.country_name = "United States"
    validation.location_name = "California"
    validation.e164_format = "+19005550199"

    carrier_res = {
        "collector": "Carrier Intelligence Collector",
        "carrier": "Unknown",
    }
    public_search_res = {
        "collector": "Public Search Collector",
        "total_results": 25,
        "unique_domains_count": 12,
    }

    res = evaluate_risk_rules(validation, carrier_res=carrier_res, public_search_res=public_search_res)

    # Premium rate (+30) + Unknown carrier (+10) + High exposure (+20) = 60 -> HIGH
    assert res["score"] == 60
    assert res["level"] == "HIGH"
    assert "Premium-Rate Number" in res["risk_findings"]
    assert "Carrier Information Unavailable" in res["risk_findings"]
    assert "High Public Exposure" in res["risk_findings"]
    assert res["public_exposure"]["level"] == "HIGH"

    # Wording check: should NOT claim "scammer", "fraud", "criminal"
    summary_lower = res["summary"].lower()
    for forbidden in ["scammer", "fraud", "criminal", "malicious"]:
        assert forbidden not in summary_lower

    # Warning symbol check
    symbols = [ind["symbol"] for ind in res["indicators"]]
    assert "⚠" in symbols


def test_risk_rules_invalid_number_negative_symbol():
    validation = MagicMock()
    validation.is_valid = False
    validation.is_possible = False
    validation.number_type = "Unknown"
    validation.country_name = "Unknown"
    validation.location_name = ""
    validation.e164_format = "123"

    res = evaluate_risk_rules(validation)

    # Invalid (+50) + Impossible (+40) + Unknown type (+10) + Unknown carrier (+10) = 100 -> HIGH
    assert res["score"] == 100
    assert res["level"] == "HIGH"
    assert "Invalid Number" in res["risk_findings"]
    assert "Impossible Number" in res["risk_findings"]

    # Negative symbol check
    symbols = [ind["symbol"] for ind in res["indicators"]]
    assert "✗" in symbols


def test_risk_rules_voip_medium_risk():
    validation = MagicMock()
    validation.is_valid = True
    validation.is_possible = True
    validation.number_type = "VoIP"
    validation.country_name = "United States"
    validation.location_name = "New York"
    validation.e164_format = "+14155552671"

    carrier_res = {"carrier": "Bandwidth.com"}
    public_search_res = {"total_results": 8, "unique_domains_count": 4}

    res = evaluate_risk_rules(validation, carrier_res=carrier_res, public_search_res=public_search_res)

    # VoIP (+15) + Moderate exposure (+10) = 25 -> LOW (or 35 if unknown carrier)
    # With carrier identified (0 carrier risk): 25 -> LOW
    assert res["score"] == 25
    assert res["level"] == "LOW"
    assert "VoIP Number" in res["risk_findings"]


def test_risk_collector_class_execution():
    validation = PhoneValidator.validate("+91 9876543210")
    collector = RiskCollector()

    res = collector.collect(validation)

    assert res["collector"] == "Risk Analysis Collector"
    assert res["category"] == "Risk Analysis"
    assert res["status"] == "success"
    assert res["success"] is True
    assert "score" in res
    assert "level" in res
    assert "indicators" in res
    assert "positive_findings" in res
    assert "risk_findings" in res
    assert "public_exposure" in res
    assert "summary" in res


def test_phone_engine_investigate_includes_risk_analysis():
    result = investigate("+91 9876543210")

    assert result["success"] is True
    assert "results" in result

    # Find Risk Analysis Collector output
    risk_col_output = next(
        (col for col in result["results"] if col.get("collector") == "Risk Analysis Collector"),
        None
    )

    assert risk_col_output is not None
    assert risk_col_output["status"] == "success"
    assert "score" in risk_col_output
    assert "level" in risk_col_output
    assert "indicators" in risk_col_output

    # Check overall investigation summary
    assert "summary" in result
    assert "appears to be a valid" in result["summary"]
