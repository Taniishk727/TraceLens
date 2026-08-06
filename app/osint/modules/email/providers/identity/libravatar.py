"""
============================================================
TraceLens Libravatar Identity Provider
============================================================

Public identity discovery provider for Libravatar.
Queries Libravatar federated CDN endpoints using MD5 and SHA256 hashes.

Author:
    TraceLens
"""

import hashlib
import logging
import time
import urllib.error
import urllib.request

from app.osint.modules.email.providers.identity.base import (
    BaseIdentityProvider,
    IdentityProviderResult,
)

logger = logging.getLogger(__name__)


class LibravatarIdentityProvider(BaseIdentityProvider):
    """
    Libravatar Identity Discovery Provider.
    """

    provider_name = "Libravatar"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def search(self, email: str) -> IdentityProviderResult:
        """
        Queries Libravatar CDN for avatar identity availability.
        """
        start_time = time.perf_counter()
        normalized_email = self.normalize_email(email)
        md5_hash = hashlib.md5(normalized_email.encode("utf-8")).hexdigest()
        sha256_hash = hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()

        avatar_check_url = f"https://seccdn.libravatar.org/avatar/{md5_hash}?d=404"
        avatar_display_url = f"https://seccdn.libravatar.org/avatar/{md5_hash}?s=200"

        logger.info(
            "[%s] Requesting identity lookup for email '%s' (hash: %s)",
            self.provider_name,
            normalized_email,
            md5_hash,
        )

        headers = {
            "User-Agent": "TraceLens OSINT Engine/1.0 (Security Research; https://tracelens.io)",
            "Accept": "*/*",
        }

        avatar_found = False
        avatar_url = None
        http_status = None
        error_message = None

        metadata = {
            "md5_hash": md5_hash,
            "sha256_hash": sha256_hash,
            "http_status": None,
        }

        try:
            req = urllib.request.Request(avatar_check_url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                http_status = resp.status
                if resp.status == 200:
                    avatar_found = True
                    avatar_url = avatar_display_url
        except urllib.error.HTTPError as err:
            http_status = err.code
        except Exception as exc:
            error_message = str(exc)

        metadata["http_status"] = http_status
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        metadata["execution_time_ms"] = elapsed_ms

        logger.info(
            "[%s] Lookup completed for '%s': Found=%s, ExecTime=%.2fms",
            self.provider_name,
            normalized_email,
            avatar_found,
            elapsed_ms,
        )

        return IdentityProviderResult(
            provider=self.provider_name,
            found=avatar_found,
            available=error_message is None or http_status is not None,
            status="completed" if avatar_found else "not_found",
            profile_url="https://www.libravatar.org" if avatar_found else None,
            display_name=None,
            username=None,
            avatar_url=avatar_url if avatar_found else None,
            bio=None,
            location=None,
            website=None,
            reason="Public Libravatar avatar discovered." if avatar_found else "No public Libravatar avatar found.",
            metadata=metadata,
        )
