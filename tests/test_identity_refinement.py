"""
============================================================
TraceLens Email Identity Intelligence Refinement Unit Tests
============================================================

Tests for:
1. Future Providers separation
2. Identity Summary & Confidence rationale
3. Unified Public Avatar merging (Gravatar & Libravatar)
4. Evidence generation & provider attribution
5. Discovered usernames extraction (no email local-part generation)
6. Username handoff candidates preparation
7. Identity Discovery Timeline steps
8. EmailEngine payload fields

Author:
    TraceLens
"""

from unittest.mock import patch, MagicMock
import pytest

from app.osint.modules.email.identity_models import (
    DiscoveredUsername,
    UsernameCandidate,
    EvidenceItem,
    UnifiedAvatarCard,
    IdentitySummary,
    TimelineStep,
)
from app.osint.modules.email.identity_processor import process_email_identity, PLANNED_PROVIDERS
from app.osint.modules.email.engine import EmailEngine, investigate


def test_identity_models_instantiation():
    uname = DiscoveredUsername(provider="Gravatar", username="cheerfullysongf28e3c3716")
    assert uname.to_dict() == {"provider": "Gravatar", "username": "cheerfullysongf28e3c3716"}

    candidate = UsernameCandidate(provider="Gravatar", username="cheerfullysongf28e3c3716", confidence="High")
    assert candidate.to_dict() == {"provider": "Gravatar", "username": "cheerfullysongf28e3c3716", "confidence": "High"}

    ev = EvidenceItem(type="Public Avatar", value="https://example.com/avatar.png", provider="GitHub")
    assert ev.to_dict() == {
        "type": "Public Avatar",
        "value": "https://example.com/avatar.png",
        "provider": "GitHub",
        "confidence": "HIGH",
    }

    card = UnifiedAvatarCard(
        avatar_url="https://example.com/avatar.png",
        display_name="Test User",
        primary_username="testuser",
        providers=["Gravatar", "Libravatar"],
        profile_urls={"Gravatar": "https://gravatar.com/testuser"},
    )
    assert card.to_dict()["providers"] == ["Gravatar", "Libravatar"]
    assert card.to_dict()["profile_urls"]["Gravatar"] == "https://gravatar.com/testuser"


def test_process_email_identity_avatar_merging_and_usernames():
    collector_results = [
        {
            "collector": "Account Presence Collector",
            "results": [
                {
                    "provider": "GitHub",
                    "status": "REGISTERED",
                    "confidence": "HIGH",
                    "username": "octocat",
                    "display_name": "The Octocat",
                    "avatar_url": "https://avatars.githubusercontent.com/u/583234",
                    "profile_url": "https://github.com/octocat",
                    "location": "San Francisco",
                    "website": "https://github.blog",
                    "bio": "GitHub Octocat",
                    "metadata": {"execution_time_ms": 12.3},
                },
                {
                    "provider": "Adobe",
                    "status": "UNSUPPORTED",
                    "confidence": "N/A",
                    "notes": "Unavailable",
                },
            ],
        },
        {
            "collector": "Public Avatar Collector",
            "providers": [
                {
                    "provider": "Gravatar",
                    "found": True,
                    "avatar_url": "https://gravatar.com/avatar/20537060b6411f684233f9f65b999967",
                    "display_name": "Gravatar User",
                    "profile_url": "https://gravatar.com/cheerfullysong",
                    "username": "cheerfullysong",
                },
                {
                    "provider": "Libravatar",
                    "found": True,
                    "avatar_url": "https://seccdn.libravatar.org/avatar/20537060b6411f684233f9f65b999967",
                    "display_name": "Gravatar User",
                    "profile_url": "https://libravatar.org/cheerfullysong",
                    "username": "cheerfullysong",
                },
            ],
        },
    ]

    res = process_email_identity(collector_results, "user@example.com")

    # 1. Discovered usernames
    usernames = res["discovered_usernames"]
    assert any(u["provider"] == "GitHub" and u["username"] == "octocat" for u in usernames)
    assert any(u["provider"] == "Gravatar" and u["username"] == "cheerfullysong" for u in usernames)

    # 2. Username candidates handoff
    candidates = res["username_candidates"]
    assert any(c["provider"] == "GitHub" and c["username"] == "octocat" and c["confidence"] == "High" for c in candidates)

    # 3. Avatar merging (Gravatar + Libravatar merged)
    avatars = res["public_avatar"]
    assert len(avatars) >= 2  # GitHub + Merged (Gravatar & Libravatar)
    merged_card = next(a for a in avatars if "Gravatar" in a["providers"])
    assert "Libravatar" in merged_card["providers"]
    assert "Visit Gravatar" in [f"Visit {k}" for k in merged_card["profile_urls"].keys()]
    assert "Visit Libravatar" in [f"Visit {k}" for k in merged_card["profile_urls"].keys()]

    # 4. Evidence items with provider attribution
    ev_items = res["evidence"]
    assert any(e["type"] == "Public Username" and e["value"] == "@octocat" and e["provider"] == "GitHub" for e in ev_items)
    assert any(e["type"] == "Public Avatar" and e["provider"] == "GitHub" for e in ev_items)

    # 5. Identity Summary & Confidence reasons rationale
    summary = res["identity_summary"]
    assert summary["profiles_found"] >= 1
    assert summary["confidence"] == "HIGH"
    assert "Public avatar found" in summary["reasons"]
    assert "Public profile found" in summary["reasons"]
    assert "Public username extracted" in summary["reasons"]
    assert "Multiple providers agree" in summary["reasons"]

    # 6. Timeline steps
    timeline = res["timeline"]
    assert timeline[0]["label"] == "Email Parsed"
    assert any(step["label"] == "Username Extracted" for step in timeline)
    assert any(step["label"] == "Avatar Retrieved" for step in timeline)
    assert any(step["label"] == "Evidence Generated" for step in timeline)

    # 7. Future providers
    assert len(res["future_providers"]) >= 7
    assert any(p["provider"] == "Adobe" for p in res["future_providers"])


def test_email_engine_investigate_exposes_all_identity_fields():
    res = investigate("test@example.com")
    assert res["success"] is True

    # Check top-level engine payload keys
    assert "identity_summary" in res
    assert "evidence" in res
    assert "public_avatar" in res
    assert "discovered_usernames" in res
    assert "username_candidates" in res
    assert "timeline" in res
    assert "future_providers" in res

    # Verify structured types
    assert isinstance(res["identity_summary"], dict)
    assert isinstance(res["evidence"], list)
    assert isinstance(res["public_avatar"], list)
    assert isinstance(res["discovered_usernames"], list)
    assert isinstance(res["username_candidates"], list)
    assert isinstance(res["timeline"], list)
    assert isinstance(res["future_providers"], list)
