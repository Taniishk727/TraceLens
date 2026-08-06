"""
============================================================
TraceLens Libravatar Avatar Provider
============================================================

Public avatar intelligence provider for Libravatar.
Queries Libravatar federated CDN endpoints using MD5 and SHA256 hashes.

Author:
    TraceLens
"""

import hashlib
import logging
import time
import urllib.error
import urllib.request

from app.osint.modules.email.providers.avatar.base import (
    BaseAvatarProvider,
    AvatarProviderResult,
)

logger = logging.getLogger(__name__)


class LibravatarProvider(BaseAvatarProvider):
    """
    Libravatar public avatar intelligence provider.
    """

    provider_name = "Libravatar"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def search(self, email: str) -> AvatarProviderResult:
        """
        Queries Libravatar CDN for public avatar availability.

        Args:
            email: Raw or normalized target email address.

        Returns:
            AvatarProviderResult containing Libravatar discovery details.
        """
        start_time = time.perf_counter()
        normalized_email = self.normalize_email(email)
        md5_hash = hashlib.md5(normalized_email.encode("utf-8")).hexdigest()
        sha256_hash = hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()

        # Libravatar HTTPS CDN endpoint with d=404 default flag
        avatar_check_url = f"https://seccdn.libravatar.org/avatar/{md5_hash}?d=404"
        avatar_display_url = f"https://seccdn.libravatar.org/avatar/{md5_hash}?s=200"

        logger.info(
            "[%s] Requesting avatar lookup for email '%s' (hash: %s) -> %s",
            self.provider_name,
            normalized_email,
            md5_hash,
            avatar_check_url,
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
            "avatar_check_url": avatar_check_url,
            "http_status": None,
        }

        try:
            req = urllib.request.Request(avatar_check_url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                http_status = resp.status
                if resp.status == 200:
                    avatar_found = True
                    avatar_url = avatar_display_url
                    logger.info(
                        "[%s] Response HTTP %d: Avatar found for '%s'",
                        self.provider_name,
                        resp.status,
                        normalized_email,
                    )
        except urllib.error.HTTPError as err:
            http_status = err.code
            if err.code == 404:
                logger.info(
                    "[%s] Response HTTP 404: No avatar found for '%s'",
                    self.provider_name,
                    normalized_email,
                )
            else:
                logger.warning(
                    "[%s] Response HTTP %d for '%s'",
                    self.provider_name,
                    err.code,
                    normalized_email,
                )
        except Exception as exc:
            error_message = str(exc)
            logger.warning(
                "[%s] Network error querying avatar endpoint for '%s': %s",
                self.provider_name,
                normalized_email,
                exc,
            )

        metadata["http_status"] = http_status
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        metadata["execution_time_ms"] = elapsed_ms

        logger.info(
            "[%s] Result for '%s': Found=%s, Status=%s, ExecTime=%.2fms",
            self.provider_name,
            normalized_email,
            avatar_found,
            http_status,
            elapsed_ms,
        )

        return AvatarProviderResult(
            provider=self.provider_name,
            available=error_message is None or http_status is not None,
            found=avatar_found,
            avatar_url=avatar_url if avatar_found else None,
            profile_url=f"https://www.libravatar.org" if avatar_found else None,
            display_name=None,
            metadata=metadata,
            error_message=error_message,
        )
