"""
============================================================
TraceLens Gravatar OSINT Collector
============================================================

Queries Gravatar public profile and avatar endpoints using the MD5
hash of normalized email addresses. Retrieves display names, avatars,
locations, bios, and linked websites.

Author:
    TraceLens
"""

import hashlib
import json
import logging
import urllib.request
import urllib.error
from typing import Any

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import EmailValidationResult

logger = logging.getLogger(__name__)


class GravatarCollector(BaseCollector):
    """
    Gravatar Profile & Avatar Collector.
    Computes MD5 hash of target email and retrieves public Gravatar profile details.
    """

    def __init__(self, timeout: float = 4.0):
        super().__init__(name="Gravatar Collector", category="Social")
        self.timeout = timeout

    def get_email_hash(self, email: str) -> str:
        """Computes lowercase MD5 hash of normalized email string."""
        normalized = email.strip().lower()
        return hashlib.md5(normalized.encode("utf-8")).hexdigest()

    def fetch_gravatar_profile(self, md5_hash: str) -> dict[str, Any]:
        """
        Fetches Gravatar JSON profile if exists.
        Returns parsed profile dict or empty dict if not found.
        """
        json_url = f"https://en.gravatar.com/{md5_hash}.json"
        req = urllib.request.Request(
            json_url,
            headers={"User-Agent": "TraceLens OSINT Engine/1.0 (Security Research)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if "entry" in data and len(data["entry"]) > 0:
                        return data["entry"][0]
        except urllib.error.HTTPError as err:
            if err.code == 404:
                logger.info("[Gravatar] No profile found for MD5 hash %s (404)", md5_hash)
            else:
                logger.warning("[Gravatar] HTTP error %d querying %s", err.code, json_url)
        except Exception as exc:
            logger.warning("[Gravatar] Failed to fetch profile for %s: %s", md5_hash, exc)

        return {}

    def check_avatar_exists(self, md5_hash: str) -> tuple[bool, str]:
        """
        Checks if avatar image exists using 404 default flag.
        """
        avatar_url = f"https://www.gravatar.com/avatar/{md5_hash}?s=200"
        check_url = f"https://www.gravatar.com/avatar/{md5_hash}?d=404"
        req = urllib.request.Request(
            check_url,
            headers={"User-Agent": "TraceLens OSINT Engine/1.0 (Security Research)"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    return True, avatar_url
        except Exception:
            pass

        return False, avatar_url

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes Gravatar intelligence collection.
        """
        email = validation.email
        md5_hash = self.get_email_hash(email)
        logger.info("[Gravatar] Checking hash %s for %s", md5_hash, email)

        # 1. Fetch JSON profile data
        profile_entry = self.fetch_gravatar_profile(md5_hash)

        # 2. Check avatar image
        avatar_exists, avatar_url = self.check_avatar_exists(md5_hash)

        if profile_entry or avatar_exists:
            display_name = profile_entry.get("displayName") or profile_entry.get("preferredUsername")
            profile_url = profile_entry.get("profileUrl") or f"https://gravatar.com/{md5_hash}"
            about = profile_entry.get("aboutMe")
            location = profile_entry.get("currentLocation")

            # Extract linked websites
            linked_websites = []
            urls_raw = profile_entry.get("urls", [])
            for u in urls_raw:
                if isinstance(u, dict) and "value" in u:
                    linked_websites.append(u["value"])
                elif isinstance(u, str):
                    linked_websites.append(u)

            logger.info("[Gravatar] Profile found for %s! Display Name: %s", email, display_name)

            return {
                "collector": self.name,
                "status": "completed",
                "gravatar_exists": True,
                "md5_hash": md5_hash,
                "avatar_url": avatar_url,
                "profile_url": profile_url,
                "display_name": display_name,
                "about": about,
                "location": location,
                "linked_websites": linked_websites,
                "reason": "Gravatar profile or custom avatar discovered.",
            }

        logger.info("[Gravatar] No Gravatar profile found for %s", email)
        return {
            "collector": self.name,
            "status": "not_found",
            "gravatar_exists": False,
            "md5_hash": md5_hash,
            "avatar_url": None,
            "profile_url": None,
            "display_name": None,
            "about": None,
            "location": None,
            "linked_websites": [],
            "reason": "No Gravatar profile or avatar found for this email address.",
        }
