"""
============================================================
TraceLens Email Identity Discovery Pipeline Unit Tests
============================================================

Tests for BaseIdentityProvider, GravatarIdentityProvider, LibravatarIdentityProvider,
GitHubIdentityProvider, GitLabIdentityProvider, StackOverflowIdentityProvider,
IdentityCollector, and EmailEngine integration.

Run:
    pytest tests/test_identity_pipeline.py -v
"""

from unittest.mock import patch, MagicMock
import urllib.error

import pytest

from app.osint.modules.email.providers.identity import (
    BaseIdentityProvider,
    IdentityProviderResult,
    GravatarIdentityProvider,
    LibravatarIdentityProvider,
    GitHubIdentityProvider,
    GitLabIdentityProvider,
    StackOverflowIdentityProvider,
)
from app.osint.modules.email.collectors.identity import IdentityCollector
from app.osint.modules.email.validator import EmailValidator
from app.osint.modules.email.engine import EmailEngine, investigate


# ==========================================================
# PROVIDER TESTS
# ==========================================================

def test_gravatar_identity_provider():
    provider = GravatarIdentityProvider()

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
                b'{"entry": [{"displayName": "Gravatar User", "preferredUsername": "gravuser", "profileUrl": "https://gravatar.com/gravuser"}]}'
            )
            return mock_resp
        mock_resp.status = 404
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.search("user@domain.com")
        assert res.provider == "Gravatar"
        assert res.found is True
        assert res.display_name == "Gravatar User"
        assert res.username == "gravuser"
        assert res.profile_url == "https://gravatar.com/gravuser"


def test_libravatar_identity_provider():
    provider = LibravatarIdentityProvider()

    def mock_urlopen(req, timeout=None):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.status = 200
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.search("user@domain.com")
        assert res.provider == "Libravatar"
        assert res.found is True
        assert "seccdn.libravatar.org" in res.avatar_url


def test_github_identity_provider():
    provider = GitHubIdentityProvider()

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
        res = provider.search("octocat@github.com")
        assert res.provider == "GitHub"
        assert res.found is True
        assert res.username == "octocat"
        assert res.display_name == "The Octocat"
        assert res.location == "San Francisco"
        assert res.website == "https://github.blog"


def test_gitlab_identity_provider():
    provider = GitLabIdentityProvider()

    def mock_urlopen(req, timeout=None):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.status = 200
        mock_resp.read.return_value = (
            b'[{"username": "gitlab_user", "name": "GitLab Dev", "web_url": "https://gitlab.com/gitlab_user", "avatar_url": "https://gitlab.com/uploads/avatar.png", "bio": "GitLab Engineer"}]'
        )
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.search("dev@gitlab.com")
        assert res.provider == "GitLab"
        assert res.found is True
        assert res.username == "gitlab_user"
        assert res.display_name == "GitLab Dev"


def test_stackoverflow_identity_provider_unsupported():
    provider = StackOverflowIdentityProvider()
    res = provider.search("anyuser@example.com")
    assert res.provider == "Stack Overflow"
    assert res.found is False
    assert res.status == "unsupported"
    assert "privacy protections" in res.reason.lower()


# ==========================================================
# COLLECTOR & PRIORITY SORTING TESTS
# ==========================================================

class MockFoundProvider(BaseIdentityProvider):
    def __init__(self, name: str, username: str):
        self.provider_name = name
        self.username = username

    def search(self, email: str) -> IdentityProviderResult:
        return IdentityProviderResult(
            provider=self.provider_name,
            found=True,
            username=self.username,
            display_name=f"{self.provider_name} User",
            avatar_url=f"https://example.com/{self.provider_name}.png",
            profile_url=f"https://example.com/{self.username}",
        )


def test_identity_collector_priority_sorting():
    # Provide Gravatar (priority 4) and GitHub (priority 1)
    g_prov = MockFoundProvider("Gravatar", "grav_user")
    gh_prov = MockFoundProvider("GitHub", "gh_user")

    collector = IdentityCollector(providers=[g_prov, gh_prov])
    validation = EmailValidator.validate("test@example.com")

    res = collector.collect(validation)

    assert res["collector"] == "Identity Discovery"
    assert res["profiles_found"] == 2
    assert res["providers_checked"] == 2

    # GitHub must be selected as primary due to higher priority
    assert res["primary_profile"]["provider"] == "GitHub"
    assert res["primary_profile"]["username"] == "gh_user"
    assert res["primary_avatar"] == "https://example.com/GitHub.png"


# ==========================================================
# ENGINE INTEGRATION TEST
# ==========================================================

def test_email_engine_identity_collector_integration():
    engine = EmailEngine()
    if not any(c.name == "Identity Discovery Collector" for c in engine._collectors):
        engine.register_collector(IdentityCollector())
    res = engine.investigate("user@domain.com")
    assert res["success"] is True

    identity_results = [r for r in res["results"] if r.get("collector") == "Identity Discovery"]
    assert len(identity_results) == 1

    col = identity_results[0]
    assert col["providers_checked"] == 5
    assert isinstance(col["profiles"], list)
