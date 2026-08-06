"""
============================================================
TraceLens GitHub Identity Provider
============================================================

Public identity discovery provider for GitHub.
Queries public GitHub REST API endpoints for user profiles matching an email address.

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


class GitHubIdentityProvider(BaseIdentityProvider):
    """
    GitHub Public Identity Discovery Provider.
    """

    provider_name = "GitHub"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def search(self, email: str) -> IdentityProviderResult:
        """
        Queries public GitHub APIs for profiles linked to the target email.
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
                    data = json.loads(resp.read().decode("utf-8"))
                    items = data.get("items", [])
                    if items:
                        first_user = items[0]
                        username = first_user.get("login")
                        profile_url = first_user.get("html_url") or f"https://github.com/{username}"
                        avatar_url = first_user.get("avatar_url")

                        # Attempt detailed user profile fetch
                        display_name = username
                        bio = None
                        location = None
                        website = None

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
                            reason="Public GitHub profile discovered for target email.",
                            metadata=metadata,
                        )
        except urllib.error.HTTPError as err:
            metadata["http_status"] = err.code
            if err.code == 403:
                logger.warning("[%s] API rate limit exceeded or forbidden (403)", self.provider_name)
                elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
                metadata["execution_time_ms"] = elapsed_ms
                return IdentityProviderResult(
                    provider=self.provider_name,
                    found=False,
                    available=True,
                    status="unsupported",
                    reason="Public GitHub API rate limit exceeded or unauthenticated lookup restricted.",
                    metadata=metadata,
                )
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
            reason="No public GitHub profile associated with this email address.",
            metadata=metadata,
        )
