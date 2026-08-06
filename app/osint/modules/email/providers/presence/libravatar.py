"""
============================================================
TraceLens Libravatar Account Presence Provider
============================================================

Account presence provider for Libravatar.
Queries Libravatar federated CDN endpoints using normalized MD5 hashes.

Author:
    TraceLens
"""

import hashlib
import logging
import time
import urllib.error
import urllib.request

from app.osint.modules.email.providers.presence.base import (
    BasePresenceProvider,
    AccountPresenceResult,
)

logger = logging.getLogger(__name__)


class LibravatarPresenceProvider(BasePresenceProvider):
    """
    Libravatar Account Presence Provider.
    """

    provider_name = "Libravatar"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check(self, email: str) -> AccountPresenceResult:
        """
        Checks for Libravatar account presence.
        """
        start_time = time.perf_counter()
        normalized_email = self.normalize_email(email)
        md5_hash = hashlib.md5(normalized_email.encode("utf-8")).hexdigest()

        avatar_check_url = f"https://seccdn.libravatar.org/avatar/{md5_hash}?d=404"
        avatar_display_url = f"https://seccdn.libravatar.org/avatar/{md5_hash}?s=200"

        logger.info(
            "[%s] Requesting account presence check for email '%s' (hash: %s)",
            self.provider_name,
            normalized_email,
            md5_hash,
        )

        headers = {
            "User-Agent": "TraceLens OSINT Engine/1.0 (Security Research; https://tracelens.io)",
            "Accept": "*/*",
        }

        avatar_exists = False
        http_status = None
        error_message = None

        metadata = {"md5_hash": md5_hash, "http_status": None}

        try:
            req = urllib.request.Request(avatar_check_url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                http_status = resp.status
                if resp.status == 200:
                    avatar_exists = True
        except urllib.error.HTTPError as err:
            http_status = err.code
        except Exception as exc:
            error_message = str(exc)

        metadata["http_status"] = http_status
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        metadata["execution_time_ms"] = elapsed_ms

        if error_message and http_status is None:
            logger.warning(
                "[%s] Error checking '%s': %s",
                self.provider_name,
                normalized_email,
                error_message,
            )
            return AccountPresenceResult(
                provider=self.provider_name,
                status="ERROR",
                confidence="LOW",
                profile_public=False,
                notes=f"Network error querying Libravatar endpoint: {error_message}",
                metadata=metadata,
            )

        if avatar_exists:
            logger.info(
                "[%s] Account REGISTERED for '%s' (ExecTime=%.2fms)",
                self.provider_name,
                normalized_email,
                elapsed_ms,
            )
            return AccountPresenceResult(
                provider=self.provider_name,
                status="REGISTERED",
                confidence="HIGH",
                profile_public=True,
                profile_url="https://www.libravatar.org",
                avatar_url=avatar_display_url,
                notes="Public Libravatar account avatar discovered.",
                metadata=metadata,
            )

        logger.info(
            "[%s] Account NOT_REGISTERED for '%s' (ExecTime=%.2fms)",
            self.provider_name,
            normalized_email,
            elapsed_ms,
        )
        return AccountPresenceResult(
            provider=self.provider_name,
            status="NOT_REGISTERED",
            confidence="HIGH",
            profile_public=False,
            notes="No public profile found.",
            metadata=metadata,
        )
