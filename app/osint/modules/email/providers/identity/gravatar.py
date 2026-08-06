"""
============================================================
TraceLens Gravatar Identity Provider
============================================================

Public identity discovery provider for Gravatar.
Queries Gravatar public profile endpoints using normalized MD5 email hashes.

Author:
    TraceLens
"""

import hashlib
import json
import logging
import time
import urllib.error
import urllib.request

from app.osint.modules.email.providers.identity.base import (
    BaseIdentityProvider,
    IdentityProviderResult,
)

logger = logging.getLogger(__name__)


class GravatarIdentityProvider(BaseIdentityProvider):
    """
    Gravatar Identity Discovery Provider.
    """

    provider_name = "Gravatar"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def search(self, email: str) -> IdentityProviderResult:
        """
        Queries Gravatar for public identity profile details.
        """
        start_time = time.perf_counter()
        normalized_email = self.normalize_email(email)
        md5_hash = hashlib.md5(normalized_email.encode("utf-8")).hexdigest()

        avatar_check_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
        avatar_display_url = f"https://www.gravatar.com/avatar/{md5_hash}?s=200"
        profile_json_url = f"https://en.gravatar.com/{md5_hash}.json"

        logger.info(
            "[%s] Requesting identity lookup for email '%s' (hash: %s)",
            self.provider_name,
            normalized_email,
            md5_hash,
        )

        headers = {
            "User-Agent": "TraceLens OSINT Engine/1.0 (Security Research; https://tracelens.io)",
            "Accept": "application/json, image/*, */*",
        }

        avatar_found = False
        avatar_url = None
        http_status = None
        profile_url = None
        display_name = None
        username = None
        bio = None
        location = None
        website = None

        metadata = {
            "md5_hash": md5_hash,
            "http_status": None,
        }

        # 1. Check Avatar Image
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
            metadata["avatar_check_error"] = str(exc)

        metadata["http_status"] = http_status

        # 2. Query Profile JSON
        profile_found = False
        try:
            req_json = urllib.request.Request(profile_json_url, headers=headers)
            with urllib.request.urlopen(req_json, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    entries = data.get("entry", [])
                    if entries:
                        entry = entries[0]
                        profile_found = True
                        display_name = entry.get("displayName")
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
                            avatar_found = True
        except urllib.error.HTTPError as err:
            metadata["profile_http_status"] = err.code
        except Exception as exc:
            metadata["profile_error"] = str(exc)

        is_found = avatar_found or profile_found
        if is_found and not profile_url:
            profile_url = f"https://gravatar.com/{md5_hash}"

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        metadata["execution_time_ms"] = elapsed_ms

        logger.info(
            "[%s] Lookup completed for '%s': Found=%s, ExecTime=%.2fms",
            self.provider_name,
            normalized_email,
            is_found,
            elapsed_ms,
        )

        return IdentityProviderResult(
            provider=self.provider_name,
            found=is_found,
            available=True,
            status="completed" if is_found else "not_found",
            profile_url=profile_url if is_found else None,
            display_name=display_name,
            username=username,
            avatar_url=avatar_url if is_found else None,
            bio=bio,
            location=location,
            website=website,
            reason="Public Gravatar profile or avatar discovered." if is_found else "No public Gravatar profile or avatar found.",
            metadata=metadata,
        )
