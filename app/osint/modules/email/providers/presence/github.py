"""
============================================================
TraceLens GitHub Account Presence Provider
============================================================

Account presence provider for GitHub.
Queries public GitHub REST API endpoints for user accounts associated with an email address.

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


class GitHubPresenceProvider(BasePresenceProvider):
    """
    GitHub Account Presence Provider.
    """

    provider_name = "GitHub"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def check(self, email: str) -> AccountPresenceResult:
        """
        Checks for GitHub account presence and extracts profile details.
        """
        start_time = time.perf_counter()
        normalized_email = self.normalize_email(email)

        query_encoded = urllib.parse.quote(f"{normalized_email} in:email")
        search_url = f"https://api.github.com/search/users?q={query_encoded}"

        headers = {
            "User-Agent": "TraceLens OSINT Engine/1.0 (Security Research; https://tracelens.io)",
            "Accept": "application/vnd.github.v3+json",
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
                    data = json.loads(resp.read().decode("utf-8"))
                    items = data.get("items", [])
                    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                    metadata["execution_time_ms"] = elapsed_ms

                    if items:
                        first_user = items[0]
                        username = first_user.get("login")
                        profile_url = first_user.get("html_url") or f"https://github.com/{username}"
                        avatar_url = first_user.get("avatar_url")
                        display_name = username
                        bio = None
                        location = None
                        website = None

                        # Fetch detailed public profile info
                        if username:
                            user_detail_url = f"https://api.github.com/users/{username}"
                            try:
                                req_detail = urllib.request.Request(user_detail_url, headers=headers)
                                with urllib.request.urlopen(req_detail, timeout=self.timeout) as resp_d:
                                    if resp_d.status == 200:
                                        d_data = json.loads(resp_d.read().decode("utf-8"))
                                        display_name = d_data.get("name") or username
                                        bio = d_data.get("bio")
                                        location = d_data.get("location")
                                        website = d_data.get("blog")
                            except Exception as exc:
                                metadata["user_detail_error"] = str(exc)

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
                            notes=f"Public GitHub account exists (username: @{username}).",
                            metadata=metadata,
                        )

                    logger.info("[%s] Account NOT_REGISTERED for '%s'", self.provider_name, normalized_email)
                    return AccountPresenceResult(
                        provider=self.provider_name,
                        status="NOT_REGISTERED",
                        confidence="MEDIUM",
                        profile_public=False,
                        notes="No public profile found.",
                        metadata=metadata,
                    )
        except urllib.error.HTTPError as err:
            metadata["http_status"] = err.code
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            metadata["execution_time_ms"] = elapsed_ms
            if err.code == 403:
                logger.warning("[%s] API rate limit hit (403)", self.provider_name)
                return AccountPresenceResult(
                    provider=self.provider_name,
                    status="UNKNOWN",
                    confidence="LOW",
                    profile_public=False,
                    notes="Public GitHub API rate limit reached. Unable to confirm presence.",
                    metadata=metadata,
                )
        except Exception as exc:
            metadata["error"] = str(exc)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        metadata["execution_time_ms"] = elapsed_ms

        return AccountPresenceResult(
            provider=self.provider_name,
            status="UNKNOWN",
            confidence="LOW",
            profile_public=False,
            notes="Unable to verify GitHub account presence due to network or endpoint response.",
            metadata=metadata,
        )
