"""
============================================================
TraceLens Account Presence Unit Tests
============================================================

Tests for BasePresenceProvider, concrete presence providers,
AccountPresenceCollector, and EmailEngine integration.

Run:
    pytest tests/test_account_presence.py -v
"""

from unittest.mock import patch, MagicMock
import urllib.error

import pytest

from app.osint.modules.email.providers.presence import (
    BasePresenceProvider,
    AccountPresenceResult,
    GravatarPresenceProvider,
    LibravatarPresenceProvider,
    GitHubPresenceProvider,
    GitLabPresenceProvider,
    RedditPresenceProvider,
    DiscordPresenceProvider,
    AdobePresenceProvider,
    SpotifyPresenceProvider,
    CanvaPresenceProvider,
    DockerPresenceProvider,
)
from app.osint.modules.email.collectors.account_presence import AccountPresenceCollector
from app.osint.modules.email.validator import EmailValidator
from app.osint.modules.email.engine import EmailEngine, investigate


# ==========================================================
# PROVIDER TESTS
# ==========================================================

def test_gravatar_presence_provider():
    provider = GravatarPresenceProvider()

    def mock_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        if "avatar" in url and "d=404" in url:
            mock_resp.status = 200
            return mock_resp
        elif ".json" in url:
            mock_resp.status = 200
            mock_resp.read.return_value = (
                b'{"entry": [{"displayName": "Test User", "preferredUsername": "testuser", "profileUrl": "https://gravatar.com/testuser"}]}'
            )
            return mock_resp
        mock_resp.status = 404
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.check("user@example.com")
        assert res.provider == "Gravatar"
        assert res.status == "REGISTERED"
        assert res.confidence == "HIGH"
        assert res.profile_url == "https://gravatar.com/testuser"
        assert res.avatar_url is not None
        assert res.display_name == "Test User"
        assert res.username == "testuser"


def test_libravatar_presence_provider():
    provider = LibravatarPresenceProvider()

    def mock_urlopen(req, timeout=None):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.status = 200
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.check("user@example.com")
        assert res.provider == "Libravatar"
        assert res.status == "REGISTERED"
        assert res.confidence == "HIGH"
        assert res.profile_url == "https://www.libravatar.org"
        assert "seccdn.libravatar.org" in res.avatar_url


def test_github_presence_provider_registered():
    provider = GitHubPresenceProvider()

    def mock_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        if "search/users" in url:
            mock_resp.status = 200
            mock_resp.read.return_value = (
                b'{"items": [{"login": "octocat", "html_url": "https://github.com/octocat", "avatar_url": "https://avatars.githubusercontent.com/u/583234"}]}'
            )
            return mock_resp
        elif "users/octocat" in url:
            mock_resp.status = 200
            mock_resp.read.return_value = (
                b'{"name": "The Octocat", "bio": "Mona Lisa Octocat", "location": "San Francisco", "blog": "https://github.blog"}'
            )
            return mock_resp
        mock_resp.status = 404
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.check("octocat@github.com")
        assert res.provider == "GitHub"
        assert res.status == "REGISTERED"
        assert res.confidence == "HIGH"
        assert res.profile_public is True
        assert res.profile_url == "https://github.com/octocat"
        assert res.avatar_url == "https://avatars.githubusercontent.com/u/583234"
        assert res.username == "octocat"
        assert res.display_name == "The Octocat"
        assert res.location == "San Francisco"
        assert res.website == "https://github.blog"


def test_gitlab_presence_provider_registered():
    provider = GitLabPresenceProvider()

    def mock_urlopen(req, timeout=None):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.status = 200
        mock_resp.read.return_value = (
            b'[{"username": "gitlabdev", "name": "GitLab Dev", "web_url": "https://gitlab.com/gitlabdev", "avatar_url": "https://gitlab.com/uploads/avatar.png"}]'
        )
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.check("dev@gitlab.com")
        assert res.provider == "GitLab"
        assert res.status == "REGISTERED"
        assert res.confidence == "HIGH"
        assert res.profile_public is True
        assert res.profile_url == "https://gitlab.com/gitlabdev"
        assert res.username == "gitlabdev"
        assert res.display_name == "GitLab Dev"


def test_unsupported_presence_providers():
    unsupported_providers = [
        RedditPresenceProvider(),
        DiscordPresenceProvider(),
        AdobePresenceProvider(),
        SpotifyPresenceProvider(),
        CanvaPresenceProvider(),
        DockerPresenceProvider(),
    ]

    for prov in unsupported_providers:
        res = prov.check("target@domain.com")
        assert res.status == "UNSUPPORTED"
        assert res.confidence == "N/A"
        assert "unavailable" in res.notes.lower() or "protections" in res.notes.lower()


# ==========================================================
# COLLECTOR & FAULT TOLERANCE TESTS
# ==========================================================

class FaultyPresenceProvider(BasePresenceProvider):
    provider_name = "FaultyProvider"

    def check(self, email: str) -> AccountPresenceResult:
        raise RuntimeError("Simulated network timeout failure")


def test_account_presence_collector_aggregation():
    g_prov = GravatarPresenceProvider()
    d_prov = DiscordPresenceProvider()
    f_prov = FaultyPresenceProvider()

    collector = AccountPresenceCollector(providers=[g_prov, d_prov, f_prov])
    validation = EmailValidator.validate("test@domain.com")

    def mock_urlopen(req, timeout=None):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.status = 200
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = collector.collect(validation)

        assert res["collector"] == "Account Presence"
        assert res["providers_checked"] == 3
        assert res["registered_accounts"] == 1
        assert res["unsupported_providers"] == 1

        faulty_item = next(r for r in res["results"] if r["provider"] == "FaultyProvider")
        assert faulty_item["status"] == "ERROR"


# ==========================================================
# ENGINE INTEGRATION TEST
# ==========================================================

def test_email_engine_account_presence_integration():
    res = investigate("user@domain.com")
    assert res["success"] is True

    presence_results = [r for r in res["results"] if r.get("collector") == "Account Presence"]
    assert len(presence_results) == 1

    col = presence_results[0]
    assert col["providers_checked"] == 10
    assert isinstance(col["results"], list)
