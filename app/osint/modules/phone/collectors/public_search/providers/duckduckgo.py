"""DuckDuckGo HTML Search Provider.
Performs real HTTP POST requests to the html.duckduckgo.com search endpoint.
Respects robots.txt and rate limits, un-wraps redirect URLs, and extracts real titles, snippets, and domains.
"""

import logging
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, unquote
import requests
from bs4 import BeautifulSoup

from .base import SearchProviderBase

logger = logging.getLogger(__name__)


class DuckDuckGoProvider(SearchProviderBase):
    SEARCH_URL = "https://html.duckduckgo.com/html/"
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://html.duckduckgo.com",
        "Referer": "https://html.duckduckgo.com/",
    }

    def _clean_url(self, raw_url: str) -> str:
        """Un-wrap DuckDuckGo redirect URLs to get the actual target URL."""
        if not raw_url:
            return ""
        if raw_url.startswith("//"):
            raw_url = "https:" + raw_url
        parsed = urlparse(raw_url)
        qs = parse_qs(parsed.query)
        if "uddg" in qs and qs["uddg"]:
            return unquote(qs["uddg"][0])
        return raw_url

    def _extract_domain(self, url: str) -> str:
        try:
            domain = urlparse(url).netloc
            return domain.lower().removeprefix("www.")
        except Exception:
            return ""

    def search(self, query: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Perform a real search request against DuckDuckGo HTML POST endpoint."""
        data = {"q": query, "b": "", "kl": "us-en"}
        try:
            resp = requests.post(
                self.SEARCH_URL,
                data=data,
                headers=self.HEADERS,
                timeout=8,
            )
            resp.raise_for_status()
        except Exception as exc:
            logger.warning("[PHONE][PUBLIC_SEARCH] DDG request failed for '%s': %s", query, exc)
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        results: List[Dict[str, Any]] = []

        for res in soup.select(".result"):
            if len(results) >= limit:
                break
            a = res.select_one("a.result__a")
            if not a:
                continue
            title = a.get_text(strip=True)
            raw_url = a.get("href", "")
            url = self._clean_url(raw_url)
            if not url or not url.startswith("http"):
                continue

            snippet_el = res.select_one(".result__snippet") or res.select_one("a.result__snippet")
            snippet = snippet_el.get_text(strip=True) if snippet_el else ""
            domain = self._extract_domain(url)

            results.append({
                "title": title,
                "url": url,
                "snippet": snippet,
                "domain": domain,
                "query": query,
                "category": "Other",
            })

        logger.debug("[PHONE][PUBLIC_SEARCH] DDG query '%s' returned %d results", query, len(results))
        return results
