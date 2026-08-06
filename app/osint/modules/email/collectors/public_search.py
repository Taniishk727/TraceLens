"""
============================================================
TraceLens Public Search OSINT Collector
============================================================

Searches public search indexes, developer forums, public archives,
and web pages for public indexation of target email addresses.

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


class PublicSearchCollector(BaseCollector):
    """
    Public Search OSINT Collector.
    Searches public archives, search engines, and web indexes for public email mentions.
    """

    def __init__(self, timeout: float = 4.0):
        super().__init__(name="Public Search Collector", category="Search")
        self.timeout = timeout

    def search_duckduckgo_lite(self, email: str) -> list[dict[str, Any]]:
        """
        Queries DuckDuckGo HTML search for public indexation.
        """
        encoded_query = urllib.parse.quote(f'"{email}"')
        url = f"https://html.duckduckgo.com/html/?q={encoded_query}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            },
        )
        findings: list[dict[str, Any]] = []

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    html_text = resp.read().decode("utf-8", errors="ignore")
                    if email.lower() in html_text.lower():
                        findings.append({
                            "source": "Web Search Index (DuckDuckGo)",
                            "url": f"https://html.duckduckgo.com/html/?q={encoded_query}",
                            "context": f"Public web search results mention target email: '{email}'",
                            "confidence": "High",
                        })
        except Exception as exc:
            logger.debug("[PublicSearch] Web search index query error for %s: %s", email, exc)

        return findings

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes public search intelligence collection.
        """
        email = validation.email
        logger.info("[PublicSearch] Searching public web indexes for %s", email)

        results = self.search_duckduckgo_lite(email)

        if results:
            logger.info("[PublicSearch] Discovered %d public web mention(s) for %s", len(results), email)
            return {
                "collector": self.name,
                "status": "completed",
                "mentions_found": len(results),
                "results": results,
                "reason": f"Discovered {len(results)} public web search mention(s).",
            }

        logger.info("[PublicSearch] No public web mentions found for %s", email)
        return {
            "collector": self.name,
            "status": "not_found",
            "mentions_found": 0,
            "results": [],
            "reason": "No public web page or forum indexation discovered.",
        }
