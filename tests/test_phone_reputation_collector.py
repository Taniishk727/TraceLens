"""
============================================================
TraceLens Phone Reputation Check Collector Unit Tests
============================================================

Tests for public search snippet keyword analysis, category mapping,
confidence evaluation, filtering of educational guides, and engine integration.
"""

from unittest.mock import MagicMock
import pytest

from app.osint.modules.phone.validator import PhoneValidator
from app.osint.modules.phone.collectors.reputation.rules import (
    evaluate_reputation_rules,
    analyze_public_search_result,
)
from app.osint.modules.phone.collectors.reputation.collector import ReputationCollector
from app.osint.modules.phone.collectors.risk.rules import evaluate_risk_rules
from app.osint.modules.phone.engine import PhoneEngine, investigate


def test_reputation_rules_detects_spam_scam_mentions():
    validation = PhoneValidator.validate("+1 415 555 2671")
    public_search_res = {
        "status": "success",
        "total_results": 2,
        "results": [
            {
                "title": "Who called from 4155552671? Reported Spam Caller",
                "snippet": "User reports receiving repeated robocall spam calls from this number.",
                "url": "https://800notes.com/Phone/1-415-555-2671",
                "domain": "800notes.com",
                "category": "Directory",
            },
            {
                "title": "Warning: Fraudulent Scam Call from +14155552671",
                "snippet": "User flagged this caller as a scammer impersonating customer support.",
                "url": "https://who-called.com/4155552671",
                "domain": "who-called.com",
                "category": "Directory",
            },
        ],
    }

    res = evaluate_reputation_rules(validation, public_search_res=public_search_res)

    assert res["reputation"] == "POTENTIAL_REPORTS"
    assert res["total_mentions"] == 2
    assert res["sources_checked"] == 2
    assert "spam" in res["categories"]
    assert "scam" in res["categories"]
    assert "robocall" in res["categories"]
    assert len(res["sources"]) == 2
    assert res["sources"][0]["confidence"] in ["MEDIUM", "HIGH", "LOW"]
    assert "disclaimer" in res


def test_reputation_rules_filters_out_educational_articles():
    validation = PhoneValidator.validate("+1 415 555 2671")
    public_search_res = {
        "status": "success",
        "total_results": 1,
        "results": [
            {
                "title": "How to prevent spam calls on iPhone and Android",
                "snippet": "Learn tips for avoiding robocalls and blocking unwanted numbers.",
                "url": "https://example.com/how-to-stop-spam-calls",
                "domain": "example.com",
                "category": "Website",
            },
        ],
    }

    res = evaluate_reputation_rules(validation, public_search_res=public_search_res)

    assert res["reputation"] == "NO_PUBLIC_REPORTS_FOUND"
    assert res["total_mentions"] == 0
    assert res["sources_checked"] == 1


def test_reputation_rules_clean_search_results():
    validation = PhoneValidator.validate("+91 9876543210")
    public_search_res = {
        "status": "success",
        "total_results": 2,
        "results": [
            {
                "title": "Official Company Contact Page",
                "snippet": "Contact customer support at +919876543210.",
                "url": "https://company.com/contact",
                "domain": "company.com",
                "category": "Business",
            },
        ],
    }

    res = evaluate_reputation_rules(validation, public_search_res=public_search_res)

    assert res["reputation"] == "NO_PUBLIC_REPORTS_FOUND"
    assert res["total_mentions"] == 0
    assert len(res["sources"]) == 0


def test_reputation_rules_unavailable_search():
    validation = PhoneValidator.validate("+91 9876543210")

    res = evaluate_reputation_rules(validation, public_search_res={"status": "unavailable"})

    assert res["reputation"] == "UNAVAILABLE"
    assert res["total_mentions"] == 0
    assert "unavailable" in res["reason"].lower()


def test_risk_collector_consumes_reputation_mentions():
    validation = PhoneValidator.validate("+1 415 555 2671")
    reputation_res = {
        "reputation": "POTENTIAL_REPORTS",
        "total_mentions": 3,
        "categories": {"spam": 2, "scam": 1},
    }

    risk_eval = evaluate_risk_rules(validation, reputation_res=reputation_res)

    # Should include warning indicator for potential public mentions
    labels = [ind["label"] for ind in risk_eval["indicators"]]
    assert "Potential Public Reputation Mentions" in labels
    assert "Potential Public Reputation Mentions" in risk_eval["risk_findings"]


def test_reputation_collector_class_execution():
    validation = PhoneValidator.validate("+91 9876543210")
    collector = ReputationCollector()

    res = collector.collect(validation, public_search_res={"status": "success", "results": []})

    assert res["collector"] == "Reputation Check Collector"
    assert res["category"] == "Reputation Check"
    assert res["status"] == "success"
    assert res["success"] is True
    assert res["reputation"] == "NO_PUBLIC_REPORTS_FOUND"
    assert "disclaimer" in res


def test_phone_engine_investigate_includes_reputation_check():
    result = investigate("+91 9876543210")

    assert result["success"] is True
    assert "results" in result

    # Find Reputation Check Collector output
    rep_col_output = next(
        (col for col in result["results"] if col.get("collector") == "Reputation Check Collector"),
        None
    )

    assert rep_col_output is not None
    assert rep_col_output["status"] in ["success", "unavailable"]
    assert "reputation" in rep_col_output

    # Check overall summary string
    assert "summary" in result
    assert "appears to be a valid" in result["summary"]
