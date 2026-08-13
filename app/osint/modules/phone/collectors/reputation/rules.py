"""
============================================================
TraceLens Phone Reputation Check - Deterministic Rules Engine
============================================================

Context-aware keyword analysis, categorization, confidence calculation,
and evidence aggregation for phone public search reputation findings.

Author:
    TraceLens
"""

import re
from typing import Any, Dict, List, Set, Tuple

# Keyword mapping to primary reputation categories
KEYWORD_CATEGORY_MAP: Dict[str, str] = {
    "spam": "spam",
    "spammer": "spam",
    "spam call": "spam",
    "spam caller": "spam",
    "scam": "scam",
    "scammer": "scam",
    "scam call": "scam",
    "fraud": "fraud",
    "fraudulent": "fraud",
    "fraud call": "fraud",
    "robocall": "robocall",
    "robocaller": "robocall",
    "telemarketing": "telemarketing",
    "telemarketer": "telemarketing",
    "phishing": "phishing",
    "vishing": "phishing",
    "harassment": "harassment",
    "harassing": "harassment",
    "suspicious": "suspicious",
    "suspicious call": "suspicious",
    "fake call": "suspicious",
    "unwanted call": "suspicious",
    "unwanted": "suspicious",
    "nuisance": "suspicious",
    "complaint": "suspicious",
    "reported number": "suspicious",
    "who called": "suspicious",
}

# Exclusion patterns for general non-target articles
EXCLUSION_PATTERNS = [
    r"how to (prevent|stop|block|avoid) spam",
    r"how to (prevent|stop|block|avoid) robocalls",
    r"guide to (avoiding|stopping) scams",
    r"tips for avoiding",
    r"what is a robocall",
    r"definition of telemarketing",
]

# Recognized authority domains for HIGH confidence
AUTHORITY_DOMAINS = [
    "ftc.gov",
    "fcc.gov",
    "donotcall.gov",
    "ic3.gov",
    "gov.uk",
    "cyber.gov.au",
    "cisa.gov",
    "police",
]

# Recognized directory & lookup domains for MEDIUM confidence
LOOKUP_DOMAINS = [
    "who-called",
    "numlookup",
    "truecaller",
    "800notes",
    "callerid",
    "phonecheck",
    "whitepages",
    "yellowpages",
    "shouldianswer",
    "reversephonelookup",
    "callermatters",
    "unknownphone",
    "nomorobo",
]


def is_educational_article(title: str, snippet: str) -> bool:
    """
    Checks if search result is a general educational article rather than a specific report.
    """
    combined = f"{title} {snippet}".lower()
    for pattern in EXCLUSION_PATTERNS:
        if re.search(pattern, combined):
            return True
    return False


def calculate_confidence(domain: str, snippet: str) -> str:
    """
    Assigns confidence level based on source domain authority and evidence specificity.
    """
    dom_lower = domain.lower()
    if any(auth in dom_lower for auth in AUTHORITY_DOMAINS):
        return "HIGH"
    elif any(lkp in dom_lower for lkp in LOOKUP_DOMAINS):
        return "MEDIUM"
    return "LOW"


def analyze_public_search_result(
    item: Dict[str, Any],
    validation: Any
) -> Tuple[List[str], str] | None:
    """
    Analyzes a single public search result item for contextual reputation indicators.

    Args:
        item: Search result dictionary (title, snippet, url, domain, category).
        validation: PhoneValidationResult instance.

    Returns:
        Tuple of (matched_categories, confidence_level) or None if no match.
    """
    title = (item.get("title") or "").strip()
    snippet = (item.get("snippet") or "").strip()
    url = (item.get("url") or "").strip()
    domain = (item.get("domain") or "").strip()

    combined_text = f"{title} {snippet} {url}".lower()

    # Filter out general educational guide articles
    if is_educational_article(title, snippet):
        return None

    # Target digits / format check for context validation
    e164 = getattr(validation, "e164_format", "") or ""
    nat_num = str(getattr(validation, "national_number", "")) or ""
    clean_e164 = re.sub(r"\D", "", e164)

    # Relevant context indicators
    has_target_mention = (
        (clean_e164 and clean_e164 in re.sub(r"\D", "", combined_text))
        or (nat_num and nat_num in re.sub(r"\D", "", combined_text))
        or any(k in combined_text for k in ["phone", "number", "caller", "call", "lookup", "who called", "reported"])
    )

    if not has_target_mention:
        return None

    # Keyword matching
    matched_categories: Set[str] = set()
    for kw, cat in KEYWORD_CATEGORY_MAP.items():
        # Match whole word or exact keyword phrase
        pattern = r"\b" + re.escape(kw) + r"\b"
        if re.search(pattern, combined_text):
            matched_categories.add(cat)

    if not matched_categories:
        return None

    confidence = calculate_confidence(domain, snippet)
    return sorted(list(matched_categories)), confidence


def evaluate_reputation_rules(
    validation: Any,
    public_search_res: Dict[str, Any] | None = None
) -> Dict[str, Any]:
    """
    Evaluates Public Search results against reputation analysis rules.

    Args:
        validation: PhoneValidationResult instance.
        public_search_res: Output dictionary from PublicSearchCollector.

    Returns:
        Structured reputation analysis result dictionary.
    """
    # Default state if search was unavailable or unperformed
    if not public_search_res or not isinstance(public_search_res, dict):
        return {
            "reputation": "UNAVAILABLE",
            "total_mentions": 0,
            "sources_checked": 0,
            "categories": {},
            "sources": [],
            "reason": "Unable to evaluate public reputation because public search results were unavailable.",
        }

    status = public_search_res.get("status")
    search_items = public_search_res.get("results", []) or []
    sources_checked = len(search_items)

    if status == "failed" or status == "unavailable":
        return {
            "reputation": "UNAVAILABLE",
            "total_mentions": 0,
            "sources_checked": 0,
            "categories": {},
            "sources": [],
            "reason": "Unable to evaluate public reputation because public search results were unavailable.",
        }

    reputation_sources: List[Dict[str, Any]] = []
    category_counts: Dict[str, int] = {
        "spam": 0,
        "scam": 0,
        "fraud": 0,
        "robocall": 0,
        "telemarketing": 0,
        "phishing": 0,
        "harassment": 0,
        "suspicious": 0,
        "other": 0,
    }

    seen_urls: Set[str] = set()

    for item in search_items:
        raw_url = item.get("url", "").strip()
        if not raw_url or raw_url in seen_urls:
            continue

        res = analyze_public_search_result(item, validation)
        if res:
            cats, confidence = res
            seen_urls.add(raw_url)

            for c in cats:
                category_counts[c] = category_counts.get(c, 0) + 1

            reputation_sources.append({
                "title": item.get("title", "").strip() or "Public Web Report",
                "url": raw_url,
                "domain": item.get("domain", "").strip() or "Web Source",
                "snippet": item.get("snippet", "").strip(),
                "categories": cats,
                "confidence": confidence,
            })

    total_mentions = len(reputation_sources)

    # Filter out categories with 0 mentions from returned category breakdown
    active_categories = {k: v for k, v in category_counts.items() if v > 0}

    if total_mentions > 0:
        reputation_status = "POTENTIAL_REPORTS"
    else:
        reputation_status = "NO_PUBLIC_REPORTS_FOUND"

    return {
        "reputation": reputation_status,
        "total_mentions": total_mentions,
        "sources_checked": sources_checked,
        "categories": active_categories,
        "all_category_counts": category_counts,
        "sources": reputation_sources,
        "disclaimer": "Public reports are unverified unless explicitly supported by an authoritative source. Absence of reports does not indicate that a number is safe.",
    }
