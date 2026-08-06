"""
============================================================
TraceLens GitLab Account Presence Provider
============================================================

Account presence provider for GitLab.
Queries public GitLab v4 REST API endpoints for user accounts matching an email address.

Author:
    TraceLens
"""

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

from app.osint.modules.email.providers.presence.base import (
    BasePresenceProvider,
    AccountPresenceResult,
)

logger = logging.getLogger(__name__)


class GitLabPresenceProvider(BasePresenceProvider):
    """
    GitLab Account Presence Provider.
    """

    provider_name = "GitLab"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check(self, email: str) -> AccountPresenceResult:
        """
        Checks for GitLab account presence and extracts profile details.
        """
        start_time = time.perf_counter()
        normalized_email = self.normalize_email(email)

        query_encoded = urllib.parse.quote(normalized_email)
        search_url = f"https://gitlab.com/api/v4/users?search={query_encoded}"

        headers = {
            "User-Agent": "TraceLens OSINT Engine/1.0 (Security Research; https://tracelens.io)",
            "Accept": "application/json",
        }

        logger.info(
            "[%s] Requesting account presence check for email '%s'",
            self.provider_name,
            normalized_email,
        )

        metadata = {"search_url": search_url, "http_status": None}

        try:
            req = urllib.request.Request(search_url, headers=headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                metadata["http_status"] = resp.status
                if resp.status == 200:
                    users = json.loads(resp.read().decode("utf-8"))
                    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    metadata["execution_time_ms"] = elapsed_ms

                    if isinstance(users, list) and users:
                        user = users[0]
                        username = user.get("username")
                        display_name = user.get("name") or username
                        profile_url = user.get("web_url") or f"https://gitlab.com/{username}"
                        avatar_url = user.get("avatar_url")
                        bio = user.get("bio")
                        location = user.get("location")
                        website = user.get("website_url") or user.get("work_information")

                        logger.info(
                            "[%s] Account REGISTERED for '%s' (username=%s)",
                            self.provider_name,
                            normalized_email,
                            username,
                        )
                        return AccountPresenceResult(
                            provider=self.provider_name,
                            status="REGISTERED",
                            confidence="HIGH",
                            profile_public=True,
                            profile_url=profile_url,
                            avatar_url=avatar_url,
                            display_name=display_name,
                            username=username,
                            bio=bio,
                            website=website,
                            location=location,
                            notes=f"Public GitLab account exists (username: @{username}).",
                            metadata=metadata,
                        )

                    logger.info("[%s] Account NOT_REGISTERED for '%s'", self.provider_name, normalized_email)
                    return AccountPresenceResult(
                        provider=self.provider_name,
                        status="NOT_REGISTERED",
                        confidence="HIGH",
                        profile_public=False,
                        notes="No public profile found.",
                        metadata=metadata,
                    )
        except urllib.error.HTTPError as err:
            metadata["http_status"] = err.code
        except Exception as exc:
            metadata["error"] = str(exc)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        metadata["execution_time_ms"] = elapsed_ms

        return AccountPresenceResult(
            provider=self.provider_name,
            status="UNKNOWN",
            confidence="LOW",
            profile_public=False,
            notes="Unable to verify GitLab account presence due to network or endpoint response.",
            metadata=metadata,
        )
