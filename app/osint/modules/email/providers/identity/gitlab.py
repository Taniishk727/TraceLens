"""
============================================================
TraceLens GitLab Identity Provider
============================================================

Public identity discovery provider for GitLab.
Queries public GitLab v4 REST API endpoints for users matching an email address.

Author:
    TraceLens
"""

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request

from app.osint.modules.email.providers.identity.base import (
    BaseIdentityProvider,
    IdentityProviderResult,
)

logger = logging.getLogger(__name__)


class GitLabIdentityProvider(BaseIdentityProvider):
    """
    GitLab Public Identity Discovery Provider.
    """

    provider_name = "GitLab"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def search(self, email: str) -> IdentityProviderResult:
        """
        Queries public GitLab API endpoints for profile matching target email.
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
            "[%s] Requesting public identity search for email '%s'",
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
                    if isinstance(users, list) and users:
                        user = users[0]
                        username = user.get("username")
                        display_name = user.get("name") or username
                        profile_url = user.get("web_url") or f"https://gitlab.com/{username}"
                        avatar_url = user.get("avatar_url")
                        bio = user.get("bio")
                        location = user.get("location")
                        website = user.get("website_url") or user.get("work_information")

                        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                        metadata["execution_time_ms"] = elapsed_ms

                        logger.info(
                            "[%s] Profile discovered for '%s': username=%s, ExecTime=%.2fms",
                            self.provider_name,
                            normalized_email,
                            username,
                            elapsed_ms,
                        )

                        return IdentityProviderResult(
                            provider=self.provider_name,
                            found=True,
                            available=True,
                            status="completed",
                            profile_url=profile_url,
                            display_name=display_name,
                            username=username,
                            avatar_url=avatar_url,
                            bio=bio,
                            location=location,
                            website=website,
                            reason="Public GitLab profile discovered for target email.",
                            metadata=metadata,
                        )
        except urllib.error.HTTPError as err:
            metadata["http_status"] = err.code
        except Exception as exc:
            metadata["error"] = str(exc)

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        metadata["execution_time_ms"] = elapsed_ms

        logger.info(
            "[%s] No public profile found for '%s' (ExecTime=%.2fms)",
            self.provider_name,
            normalized_email,
            elapsed_ms,
        )

        return IdentityProviderResult(
            provider=self.provider_name,
            found=False,
            available=True,
            status="not_found",
            reason="No public GitLab profile associated with this email address.",
            metadata=metadata,
        )
