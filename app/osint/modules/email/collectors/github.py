"""
============================================================
TraceLens Public Git OSINT Collector
============================================================

Searches public Git commit records and GitHub public profiles for
author attribution matching the target email address.

Author:
    TraceLens
"""

import json
import logging
import urllib.request
import urllib.parse
import urllib.error
from typing import Any

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import EmailValidationResult

logger = logging.getLogger(__name__)


class GitCollector(BaseCollector):
    """
    Public Git OSINT Collector.
    Searches public GitHub commits and user directories for public commit attributions,
    author names, public repositories, organizations, and profile URLs.
    """

    def __init__(self, timeout: float = 4.0):
        super().__init__(name="Public Git Collector", category="Identity")
        self.timeout = timeout

    def search_github_users(self, email: str) -> dict[str, Any] | None:
        """Searches GitHub user search API for email match."""
        url = f"https://api.github.com/search/users?q={urllib.parse.quote(email)}+in:email"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "TraceLens OSINT Engine/1.0 (Security Research)",
                "Accept": "application/vnd.github.v3+json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("total_count", 0) > 0:
                        items = data.get("items", [])
                        return items[0]
        except urllib.error.HTTPError as err:
            if err.code in (403, 429):
                logger.info("[Git] GitHub API rate limit reached during user search")
                return {"rate_limited": True}
        except Exception as exc:
            logger.debug("[Git] User search failed for %s: %s", email, exc)

        return None

    def search_github_commits(self, email: str) -> dict[str, Any]:
        """Searches GitHub public commit search API by author-email."""
        url = f"https://api.github.com/search/commits?q=author-email:{urllib.parse.quote(email)}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "TraceLens OSINT Engine/1.0 (Security Research)",
                "Accept": "application/vnd.github.cloak-preview+json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return data
        except urllib.error.HTTPError as err:
            if err.code in (403, 429):
                logger.info("[Git] GitHub API rate limit reached during commit search")
                return {"rate_limited": True}
        except Exception as exc:
            logger.debug("[Git] Commit search failed for %s: %s", email, exc)

        return {}

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes public Git intelligence collection.
        """
        email = validation.email
        logger.info("[Git] Searching public Git attributions for %s", email)

        # 1. Search GitHub Users
        user_match = self.search_github_users(email)
        rate_limited = False

        if isinstance(user_match, dict) and user_match.get("rate_limited"):
            rate_limited = True
            user_match = None

        # 2. Search GitHub Commits
        commit_data = self.search_github_commits(email)
        if commit_data.get("rate_limited"):
            rate_limited = True

        commit_count = commit_data.get("total_count", 0)
        commit_items = commit_data.get("items", [])

        author_names: set[str] = set()
        repositories: set[str] = set()
        organizations: set[str] = set()
        public_profile: str | None = None

        if user_match:
            username = user_match.get("login")
            public_profile = user_match.get("html_url") or f"https://github.com/{username}"
            if username:
                author_names.add(username)

        for item in commit_items:
            commit_obj = item.get("commit", {})
            author_obj = commit_obj.get("author", {})
            name = author_obj.get("name")
            if name:
                author_names.add(name)

            repo_obj = item.get("repository", {})
            full_name = repo_obj.get("full_name")
            if full_name:
                repositories.add(full_name)
                owner = repo_obj.get("owner", {}).get("login")
                if owner:
                    organizations.add(owner)

        has_findings = bool(user_match or commit_count > 0 or repositories)

        if has_findings:
            logger.info("[Git] Public Git findings for %s: %d commit(s), %d repo(s)", email, commit_count, len(repositories))
            return {
                "collector": self.name,
                "status": "completed",
                "author_name": list(author_names)[0] if author_names else None,
                "author_names": list(author_names),
                "repositories": list(repositories)[:10],
                "organizations": list(organizations)[:5],
                "commit_count": commit_count,
                "public_profile": public_profile,
                "reason": f"Discovered public Git commits across {len(repositories)} repository(ies).",
            }

        if rate_limited:
            logger.info("[Git] GitHub API rate limit encountered for %s", email)
            return {
                "collector": self.name,
                "status": "unavailable",
                "author_name": None,
                "author_names": [],
                "repositories": [],
                "organizations": [],
                "commit_count": 0,
                "public_profile": None,
                "reason": "Public Git search unavailable (GitHub API rate limit reached).",
            }

        logger.info("[Git] No public Git attributions found for %s", email)
        return {
            "collector": self.name,
            "status": "not_found",
            "author_name": None,
            "author_names": [],
            "repositories": [],
            "organizations": [],
            "commit_count": 0,
            "public_profile": None,
            "reason": "No public Git commit attributions or profiles found.",
        }
