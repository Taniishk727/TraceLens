"""Public Search Collector for Phone module.
Automated Public Web Intelligence Collector.
Executes public web searches across multiple search categories concurrently,
collects, deduplicates, categorizes real results, and returns structured findings.
"""

from typing import Any, List, Dict, Set
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from app.osint.modules.phone.base import BasePhoneCollector
from app.osint.modules.phone.validator import PhoneValidationResult
from .providers.base import SearchProviderBase
from .providers.duckduckgo import DuckDuckGoProvider

logger = logging.getLogger(__name__)

# Configurable limits
MAX_RESULTS_PER_QUERY = 10
MAX_TOTAL_RESULTS = 30
CONCURRENT_WORKERS = 4


def normalize_url_for_dedup(url: str) -> str:
    """Normalize a URL to strip tracking parameters and trailing slashes for deduplication."""
    try:
        parsed = urlparse(url)
        clean_netloc = parsed.netloc.lower().removeprefix("www.")
        clean_path = parsed.path.rstrip("/")
        # Filter out tracking query params
        qs = parse_qs(parsed.query)
        filtered_qs = {k: v for k, v in qs.items() if not k.startswith("utm_") and k != "ref"}
        sorted_qs = "&".join(f"{k}={v[0]}" for k, v in sorted(filtered_qs.items()))
        query_str = f"?{sorted_qs}" if sorted_qs else ""
        return f"{parsed.scheme}://{clean_netloc}{clean_path}{query_str}"
    except Exception:
        return url.strip().rstrip("/")


def categorize_result(item: Dict[str, Any]) -> str:
    """Categorize a search result using domain, URL, title, and snippet heuristics."""
    domain = item.get("domain", "").lower()
    snippet = item.get("snippet", "").lower()
    title = item.get("title", "").lower()
    url = item.get("url", "").lower()

    # 1. Social/Profile
    if any(k in domain for k in ["linkedin.com", "facebook.com", "twitter.com", "x.com", "instagram.com", "github.com", "pinterest.com"]):
        return "Social/Profile"
    if "reddit.com/user" in url or "user profile" in snippet:
        return "Social/Profile"

    # 2. Directory
    if any(k in domain for k in ["yellowpages", "whitepages", "truecaller", "whois", "numlookup", "directory", "411", "phonebook", "lookup"]):
        return "Directory"
    if any(k in snippet or k in title for k in ["phone directory", "white pages", "yellow pages", "caller id", "who is", "phone lookup", "directory"]):
        return "Directory"

    # 3. Document
    if url.endswith((".pdf", ".doc", ".docx", ".xls", ".xlsx")) or any(k in snippet for k in ["[pdf]", "[doc]", "filetype:pdf", "pdf document"]):
        return "Document"

    # 4. Forum
    if any(k in domain for k in ["reddit.com", "quora.com", "stackoverflow.com", "forum", "community", "discussions"]):
        return "Forum"
    if any(k in snippet or k in title for k in ["forum", "thread", "discussion", "community"]):
        return "Forum"

    # 5. News
    if any(k in domain for k in ["news", "press", "reuters", "bloomberg", "bbc", "cnn", "nytimes"]):
        return "News"
    if any(k in snippet or k in title for k in ["news", "press release", "article", "headline", "breaking"]):
        return "News"

    # 6. Business
    if any(k in domain for k in ["biz", "company", "inc", "llc", "corp", "store", "shop", "office", "services", "business"]):
        return "Business"
    if any(k in snippet or k in title for k in ["company", "contact us", "office", "business", "services", "headquarters", "customer service"]):
        return "Business"

    # 7. Website
    if domain:
        return "Website"

    return "Other"


class PublicSearchCollector(BasePhoneCollector):
    """Automated Public Search Collector for Phone numbers."""

    def __init__(self, provider: SearchProviderBase | None = None):
        super().__init__(
            name="Public Search Collector",
            category="Public Search",
            enabled=True,
        )
        self.provider = provider or DuckDuckGoProvider()

    def _generate_queries(self, validation: PhoneValidationResult) -> List[str]:
        e164 = validation.e164_format
        nat_num = str(validation.national_number)
        intl_fmt = validation.international_format

        raw_queries = [
            # A. General Web
            f'"{e164}"',
            f'"{nat_num}"',
            f'"{intl_fmt}"',
            # B. Business
            f'"{e164}" business',
            f'"{e164}" company',
            f'"{e164}" contact',
            # C. Directory
            f'"{e164}" directory',
            f'"{e164}" listing',
            f'"{e164}" phone',
            # D. Documents
            f'"{e164}" filetype:pdf',
            f'"{e164}" filetype:doc',
            f'"{e164}" filetype:xls',
            # E. Forums
            f'"{e164}" forum',
            f'"{e164}" discussion',
            # F. News
            f'"{e164}" news',
        ]

        # Deduplicate preserving order
        queries = []
        seen = set()
        for q in raw_queries:
            if q not in seen:
                seen.add(q)
                queries.append(q)
        return queries

    def collect(self, validation: PhoneValidationResult) -> Dict[str, Any]:
        queries = self._generate_queries(validation)

        logger.info("[PHONE][PUBLIC_SEARCH] Starting automated searches for %s across %d queries", validation.e164_format, len(queries))

        collected_items: List[Dict[str, Any]] = []
        seen_normalized_urls: Set[str] = set()

        def _execute_query(q: str) -> List[Dict[str, Any]]:
            logger.info("[PHONE][PUBLIC_SEARCH] Querying: %s", q)
            try:
                return self.provider.search(q, limit=MAX_RESULTS_PER_QUERY)
            except Exception as exc:
                logger.warning("[PHONE][PUBLIC_SEARCH] Error querying '%s': %s", q, exc)
                return []

        # Execute queries concurrently using ThreadPoolExecutor
        max_workers = min(len(queries), CONCURRENT_WORKERS) or 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_query = {executor.submit(_execute_query, q): q for q in queries}
            for future in as_completed(future_to_query):
                q = future_to_query[future]
                try:
                    items = future.result()
                except Exception as exc:
                    logger.error("[PHONE][PUBLIC_SEARCH] Execution error for '%s': %s", q, exc)
                    continue

                for item in items:
                    raw_url = item.get("url", "")
                    if not raw_url:
                        continue
                    norm_url = normalize_url_for_dedup(raw_url)
                    if norm_url in seen_normalized_urls:
                        continue
                    seen_normalized_urls.add(norm_url)

                    # Categorize and store
                    item["category"] = categorize_result(item)
                    item["query"] = q
                    collected_items.append(item)

                    if len(collected_items) >= MAX_TOTAL_RESULTS:
                        break

                if len(collected_items) >= MAX_TOTAL_RESULTS:
                    break

        # Calculate category breakdown (ONLY categories with > 0 results)
        breakdown: Dict[str, int] = {}
        unique_domains: Set[str] = set()

        for item in collected_items:
            cat = item.get("category", "Other")
            breakdown[cat] = breakdown.get(cat, 0) + 1
            domain = item.get("domain", "")
            if domain:
                unique_domains.add(domain)

        total_results = len(collected_items)
        unique_domains_count = len(unique_domains)

        logger.info(
            "[PHONE][PUBLIC_SEARCH] Completed. Total unique results: %d across %d domains. Breakdown: %s",
            total_results,
            unique_domains_count,
            breakdown,
        )

        status = "success" if total_results > 0 else "no_results"

        return {
            "collector": self.name,
            "category": self.category,
            "status": status,
            "phone": validation.e164_format,
            "total_results": total_results,
            "unique_domains_count": unique_domains_count,
            "breakdown": breakdown,
            "results": collected_items,
        }
