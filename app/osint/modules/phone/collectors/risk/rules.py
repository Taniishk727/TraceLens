"""
============================================================
TraceLens Phone Risk Collector - Deterministic Rules Engine
============================================================

Contains explicit, rule-based scoring logic, weight definitions,
and indicator evaluation for phone number OSINT risk assessment.

Author:
    TraceLens
"""

from typing import Any, Dict, List

# Scoring Weights
WEIGHT_INVALID_NUMBER = 50
WEIGHT_IMPOSSIBLE_NUMBER = 40
WEIGHT_PREMIUM_RATE = 30
WEIGHT_TOLL_FREE = 15
WEIGHT_SHARED_COST = 15
WEIGHT_VOIP = 15
WEIGHT_PAGER = 15
WEIGHT_PERSONAL_NUMBER = 15
WEIGHT_UNKNOWN_TYPE = 10
WEIGHT_UNKNOWN_CARRIER = 10
WEIGHT_UNUSUAL_FORMAT = 10
WEIGHT_EXPOSURE_MODERATE = 10
WEIGHT_EXPOSURE_HIGH = 20
WEIGHT_REPUTATION_MENTIONS = 15


def classify_risk_level(score: int) -> str:
    """
    Classifies risk score into standardized risk levels:
    0-29   = LOW
    30-59  = MEDIUM
    60-100 = HIGH
    """
    if score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


def evaluate_risk_rules(
    validation: Any,
    carrier_res: Dict[str, Any] | None = None,
    public_search_res: Dict[str, Any] | None = None,
    reputation_res: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """
    Evaluates phone investigation outputs against deterministic risk rules.

    Args:
        validation: PhoneValidationResult dataclass instance.
        carrier_res: Dictionary output from CarrierCollector.
        public_search_res: Dictionary output from PublicSearchCollector.

    Returns:
        Structured risk analysis result dictionary.
    """
    score = 0
    indicators: List[Dict[str, str]] = []
    positive_findings: List[str] = []
    risk_findings: List[str] = []

    # ----------------------------------------------------
    # 1. Validation & Structure Rules
    # ----------------------------------------------------
    is_valid = getattr(validation, "is_valid", False)
    is_possible = getattr(validation, "is_possible", False)
    number_type = getattr(validation, "number_type", "Unknown") or "Unknown"
    country_name = getattr(validation, "country_name", "Unknown") or "Unknown"
    location_name = getattr(validation, "location_name", "") or ""
    e164 = getattr(validation, "e164_format", "") or ""

    if is_valid:
        positive_findings.append("Valid Number")
        indicators.append({
            "type": "positive",
            "symbol": "✓",
            "label": "Valid Number",
            "reason": "Number passed structural validation."
        })
    else:
        score += WEIGHT_INVALID_NUMBER
        risk_findings.append("Invalid Number")
        indicators.append({
            "type": "negative",
            "symbol": "✗",
            "label": "Invalid Number",
            "reason": "Number failed structural validation."
        })

    if is_possible:
        positive_findings.append("Possible Number")
        indicators.append({
            "type": "positive",
            "symbol": "✓",
            "label": "Possible Number",
            "reason": "Number matches standard length and structure."
        })
    else:
        score += WEIGHT_IMPOSSIBLE_NUMBER
        risk_findings.append("Impossible Number")
        indicators.append({
            "type": "negative",
            "symbol": "✗",
            "label": "Impossible Number",
            "reason": "Number fails basic length or prefix rules."
        })

    if country_name and country_name != "Unknown":
        positive_findings.append("Country Identified")
        indicators.append({
            "type": "positive",
            "symbol": "✓",
            "label": "Country Identified",
            "reason": f"Associated country identified ({country_name})."
        })

    if location_name and location_name.strip():
        positive_findings.append("Region Identified")
        indicators.append({
            "type": "positive",
            "symbol": "✓",
            "label": "Region Identified",
            "reason": f"Geographic region identified ({location_name})."
        })

    # Standard E.164 formatting
    if e164 and e164.startswith("+") and len(e164) >= 8:
        positive_findings.append("Standard Numbering Format")
        indicators.append({
            "type": "positive",
            "symbol": "✓",
            "label": "Standard Numbering Format",
            "reason": "Follows standard ITU-T E.164 international format."
        })

    # ----------------------------------------------------
    # 2. Number Type Rules
    # ----------------------------------------------------
    type_normalized = number_type.strip()

    if type_normalized in ["Mobile", "Fixed Line", "Fixed Line or Mobile"]:
        label_text = "Mobile" if "Mobile" in type_normalized else "Landline"
        positive_findings.append("Standard Number Type")
        indicators.append({
            "type": "positive",
            "symbol": "✓",
            "label": "Standard Number Type",
            "reason": f"Standard {type_normalized.lower()} line."
        })
    elif type_normalized == "Premium Rate":
        score += WEIGHT_PREMIUM_RATE
        risk_findings.append("Premium-Rate Number")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "Premium-Rate Number",
            "reason": "Number is classified as a premium rate service."
        })
    elif type_normalized == "VoIP":
        score += WEIGHT_VOIP
        risk_findings.append("VoIP Number")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "VoIP Number",
            "reason": "Number is registered as Voice over IP (VoIP), which can be easily provisioned remotely."
        })
    elif type_normalized == "Toll Free":
        score += WEIGHT_TOLL_FREE
        risk_findings.append("Toll-Free Number")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "Toll-Free Number",
            "reason": "Number is classified as a toll-free service line."
        })
    elif type_normalized == "Shared Cost":
        score += WEIGHT_SHARED_COST
        risk_findings.append("Shared-Cost Number")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "Shared-Cost Number",
            "reason": "Number is classified as a shared-cost service."
        })
    elif type_normalized == "Pager":
        score += WEIGHT_PAGER
        risk_findings.append("Pager Number")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "Pager Number",
            "reason": "Number is classified as a pager service."
        })
    elif type_normalized == "Personal Number":
        score += WEIGHT_PERSONAL_NUMBER
        risk_findings.append("Personal Number Service")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "Personal Number Service",
            "reason": "Number is registered under a flexible personal numbering scheme."
        })
    else:
        score += WEIGHT_UNKNOWN_TYPE
        risk_findings.append("Unknown Number Type")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "Unknown Number Type",
            "reason": "Number type could not be definitively determined."
        })

    # ----------------------------------------------------
    # 3. Carrier Intelligence Rules
    # ----------------------------------------------------
    carrier_name = "Unknown"
    if carrier_res and isinstance(carrier_res, dict):
        carrier_name = carrier_res.get("carrier", "Unknown") or "Unknown"

    if carrier_name and carrier_name != "Unknown":
        positive_findings.append("Carrier Identified")
        indicators.append({
            "type": "positive",
            "symbol": "✓",
            "label": "Carrier Identified",
            "reason": f"Operating carrier identified ({carrier_name})."
        })
    else:
        score += WEIGHT_UNKNOWN_CARRIER
        risk_findings.append("Carrier Information Unavailable")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "Carrier Information Unavailable",
            "reason": "Network carrier information is not registered or unavailable."
        })

    # ----------------------------------------------------
    # 4. Public Exposure Rules
    # ----------------------------------------------------
    ref_count = 0
    domain_count = 0
    exposure_level = "NONE"

    if public_search_res and isinstance(public_search_res, dict):
        ref_count = public_search_res.get("total_results", 0) or 0
        domain_count = public_search_res.get("unique_domains_count", 0) or 0

    if ref_count >= 20:
        exposure_level = "HIGH"
        score += WEIGHT_EXPOSURE_HIGH
        risk_findings.append("High Public Exposure")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "High Public Exposure",
            "reason": f"Number appears in {ref_count} public web references across {domain_count} domains."
        })
    elif ref_count >= 6:
        exposure_level = "MODERATE"
        score += WEIGHT_EXPOSURE_MODERATE
        risk_findings.append("Moderate Public Exposure")
        indicators.append({
            "type": "warning",
            "symbol": "⚠",
            "label": "Moderate Public Exposure",
            "reason": f"Number appears in {ref_count} public web references across {domain_count} domains."
        })
    elif ref_count >= 1:
        exposure_level = "LOW"
        positive_findings.append("Low Public Exposure")
        indicators.append({
            "type": "positive",
            "symbol": "✓",
            "label": "Low Public Exposure",
            "reason": f"{ref_count} public reference{'s' if ref_count > 1 else ''} discovered across web listings."
        })

    # ----------------------------------------------------
    # 4b. Reputation Check Integration Rules
    # ----------------------------------------------------
    if reputation_res and isinstance(reputation_res, dict):
        total_rep_mentions = reputation_res.get("total_mentions", 0) or 0
        rep_status = reputation_res.get("reputation", "")

        if total_rep_mentions > 0:
            rep_weight = min(25, total_rep_mentions * 10)
            score += rep_weight
            risk_findings.append("Potential Public Reputation Mentions")
            indicators.append({
                "type": "warning",
                "symbol": "⚠",
                "label": "Potential Public Reputation Mentions",
                "reason": f"{total_rep_mentions} potential public reputation mention{'s' if total_rep_mentions > 1 else ''} discovered in search snippets."
            })
        elif rep_status == "NO_PUBLIC_REPORTS_FOUND":
            positive_findings.append("No Public Reputation Reports")
            indicators.append({
                "type": "positive",
                "symbol": "✓",
                "label": "No Public Reputation Reports",
                "reason": "No relevant public reputation reports were discovered in the sources checked."
            })

    # ----------------------------------------------------
    # 5. Score Normalization & Level Assignment
    # ----------------------------------------------------
    score = max(0, min(100, score))
    level = classify_risk_level(score)

    # ----------------------------------------------------
    # 6. Natural Language Summary Generation
    # ----------------------------------------------------
    if level == "HIGH":
        reasons_list = []
        if "Premium-Rate Number" in risk_findings:
            reasons_list.append("detected number type (Premium Rate)")
        elif "VoIP Number" in risk_findings:
            reasons_list.append("detected number type (VoIP)")
        elif "Invalid Number" in risk_findings:
            reasons_list.append("invalid structural formatting")

        if exposure_level == "HIGH":
            reasons_list.append("high public web exposure")

        reasons_str = " and ".join(reasons_list) if reasons_list else "detected number characteristics and public exposure"
        summary = (
            f"This number contains characteristics that warrant additional investigation. "
            f"The risk classification is based on {reasons_str}."
        )
    elif level == "MEDIUM":
        summary = (
            f"Moderate risk indicators were detected for this number. "
            f"Assessment reflects specific line features or public exposure profile."
        )
    else:
        summary = "No significant risk indicators detected."

    public_exposure_info = {
        "references": ref_count,
        "unique_domains": domain_count,
        "level": exposure_level,
    }

    return {
        "score": score,
        "level": level,
        "indicators": indicators,
        "positive_findings": positive_findings,
        "risk_findings": risk_findings,
        "public_exposure": public_exposure_info,
        "summary": summary,
    }
