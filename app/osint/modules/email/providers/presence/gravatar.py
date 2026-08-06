"""
============================================================
TraceLens Gravatar Account Presence Provider
============================================================

Account presence provider for Gravatar.
Queries Gravatar public profile and avatar endpoints using normalized MD5 hashes.

Author:
    TraceLens
"""

import hashlib
import json
import logging
import time
import urllib.error
import urllib.request

from app.osint.modules.email.providers.presence.base import (
    BasePresenceProvider,
    AccountPresenceResult,
)

logger = logging.getLogger(__name__)


class GravatarPresenceProvider(BasePresenceProvider):
    """
    Gravatar Account Presence Provider.
    """

    provider_name = "Gravatar"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check(self, email: str) -> AccountPresenceResult:
        """
        Checks for Gravatar account presence and extracts profile details.
        """
        start_time = time.perf_counter()
        normalized_email = self.normalize_email(email)
        md5_hash = hashlib.md5(normalized_email.encode("utf-8")).hexdigest()

        avatar_check_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
        avatar_display_url = f"https://www.gravatar.com/avatar/{md5_hash}?s=200"
        profile_json_url = f"https://en.gravatar.com/{md5_hash}.json"

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
        profile_exists = False
        http_status = None

        display_name = None
        username = None
        bio = None
        location = None
        website = None
        profile_url = None
        avatar_url = None

        metadata = {"md5_hash": md5_hash, "http_status": None}

        # 1. Check Avatar Image
        try:
            req = urllib.request.Request(avatar_check_url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                http_status = resp.status
                if resp.status == 200:
                    avatar_exists = True
                    avatar_url = avatar_display_url
        except urllib.error.HTTPError as err:
            http_status = err.code
        except Exception as exc:
            metadata["avatar_check_error"] = str(exc)

        metadata["http_status"] = http_status

        # 2. Check JSON Profile
        try:
            req_json = urllib.request.Request(profile_json_url, headers=headers)
            with urllib.request.urlopen(req_json, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    entries = data.get("entry", [])
                    if entries:
                        entry = entries[0]
                        profile_exists = True
                        display_name = entry.get("displayName") or entry.get("preferredUsername")
                        username = entry.get("preferredUsername")
                        profile_url = entry.get("profileUrl") or f"https://gravatar.com/{md5_hash}"
                        bio = entry.get("aboutMe")
                        location = entry.get("currentLocation")

                        urls = entry.get("urls", [])
                        if urls and isinstance(urls[0], dict) and "value" in urls[0]:
                            website = urls[0]["value"]
                        elif urls and isinstance(urls[0], str):
                            website = urls[0]

                        if not avatar_url and entry.get("thumbnailUrl"):
                            avatar_url = entry.get("thumbnailUrl")
                            avatar_exists = True
        except Exception:
            pass

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        metadata["execution_time_ms"] = elapsed_ms

        if avatar_exists or profile_exists:
            if not profile_url:
                profile_url = f"https://gravatar.com/{md5_hash}"

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
                profile_public=profile_exists or avatar_exists,
                profile_url=profile_url,
                avatar_url=avatar_url,
                display_name=display_name,
                username=username,
                bio=bio,
                website=website,
                location=location,
                notes="Public Gravatar account discovered.",
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
