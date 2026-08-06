"""
============================================================
TraceLens Public Avatar Intelligence Unit Tests
============================================================

Tests for BaseAvatarProvider, GravatarProvider, LibravatarProvider,
AvatarCollector, and EmailEngine integration.

Run:
    pytest tests/test_avatar_provider.py -v
"""

from unittest.mock import patch, MagicMock
import urllib.error

import pytest

from app.osint.modules.email.providers.avatar import (
    BaseAvatarProvider,
    AvatarProviderResult,
    GravatarProvider,
    LibravatarProvider,
)
from app.osint.modules.email.collectors.avatar import AvatarCollector
from app.osint.modules.email.validator import EmailValidator
from app.osint.modules.email.engine import EmailEngine, investigate


# ==========================================================
# GRAVATAR PROVIDER TESTS
# ==========================================================

def test_gravatar_provider_found():
    provider = GravatarProvider()
    
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
                b'{"entry": [{"displayName": "Test User", "profileUrl": "https://gravatar.com/testuser"}]}'
            )
            return mock_resp
        mock_resp.status = 404
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.search("  TEST.USER@example.com  ")
        assert res.provider == "Gravatar"
        assert res.available is True
        assert res.found is True
        assert "avatar/a775546e5a4e4ac660cd78a61cd90bb3" in res.avatar_url
        assert res.display_name == "Test User"
        assert res.profile_url == "https://gravatar.com/testuser"
        assert res.metadata["http_status"] == 200


def test_gravatar_provider_not_found():
    provider = GravatarProvider()

    def mock_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            url="https://www.gravatar.com/avatar/...",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.search("nonexistent@example.com")
        assert res.provider == "Gravatar"
        assert res.available is True
        assert res.found is False
        assert res.avatar_url is None
        assert res.metadata["http_status"] == 404


# ==========================================================
# LIBRAVATAR PROVIDER TESTS
# ==========================================================

def test_libravatar_provider_found():
    provider = LibravatarProvider()

    def mock_urlopen(req, timeout=None):
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_resp.status = 200
        return mock_resp

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.search("User@Domain.com")
        assert res.provider == "Libravatar"
        assert res.available is True
        assert res.found is True
        assert "seccdn.libravatar.org" in res.avatar_url
        assert res.metadata["http_status"] == 200


def test_libravatar_provider_not_found():
    provider = LibravatarProvider()

    def mock_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            url="https://seccdn.libravatar.org/avatar/...",
            code=404,
            msg="Not Found",
            hdrs={},
            fp=None,
        )

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = provider.search("User@Domain.com")
        assert res.provider == "Libravatar"
        assert res.available is True
        assert res.found is False
        assert res.avatar_url is None
        assert res.metadata["http_status"] == 404


# ==========================================================
# AVATAR COLLECTOR & ERROR ISOLATION TESTS
# ==========================================================

class FailingProvider(BaseAvatarProvider):
    provider_name = "FaultyProvider"

    def search(self, email: str) -> AvatarProviderResult:
        raise RuntimeError("Simulated network timeout failure")


def test_avatar_collector_concurrency_and_fault_tolerance():
    g_prov = GravatarProvider()
    l_prov = LibravatarProvider()
    f_prov = FailingProvider()

    collector = AvatarCollector(providers=[g_prov, l_prov, f_prov])
    validation = EmailValidator.validate("test@example.com")

    def mock_urlopen(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        if "gravatar" in url and "d=404" in url:
            mock_resp.status = 200
            return mock_resp
        elif "libravatar" in url:
            raise urllib.error.HTTPError(
                url=url, code=404, msg="Not Found", hdrs={}, fp=None
            )
        raise urllib.error.HTTPError(
            url=url, code=404, msg="Not Found", hdrs={}, fp=None
        )

    with patch("urllib.request.urlopen", side_effect=mock_urlopen):
        res = collector.collect(validation)

        assert res["collector"] == "Public Avatar"
        assert res["providers_checked"] == 3
        assert res["avatars_found"] == 1
        assert res["best_avatar"] is not None
        assert res["best_avatar"]["provider"] == "Gravatar"

        provider_names = [p["provider"] for p in res["providers"]]
        assert "Gravatar" in provider_names
        assert "Libravatar" in provider_names
        assert "FaultyProvider" in provider_names

        faulty_res = next(p for p in res["providers"] if p["provider"] == "FaultyProvider")
        assert faulty_res["available"] is False
        assert "Simulated network timeout failure" in faulty_res["error_message"]


# ==========================================================
# ENGINE INTEGRATION TEST
# ==========================================================

def test_email_engine_avatar_collector_integration():
    engine = EmailEngine()
    if not any(c.name in ("Public Avatar Collector", "Public Avatar") for c in engine._collectors):
        engine.register_collector(AvatarCollector())
    res = engine.investigate("user@gmail.com")
    assert res["success"] is True
    
    avatar_results = [r for r in res["results"] if r.get("collector") in ("Public Avatar Collector", "Public Avatar")]
    assert len(avatar_results) == 1
    
    col = avatar_results[0]
    assert col["providers_checked"] == 2
    assert isinstance(col["providers"], list)
