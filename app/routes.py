from flask import Blueprint, render_template, request, jsonify

from app.osint.engine import investigate
from app.osint.modules.username.data.username_sites import SITES

main = Blueprint("main", __name__)



# Pre-build the slim platform list once at import time for the animation.
_PLATFORMS_FOR_JS = [
    {
        "name"     : s["name"],
        "category" : s.get("category", "Other"),
        "transport": s.get("transport", "requests"),
    }
    for s in SITES
]


# ----------------------------------------
# Home Page
# ----------------------------------------
@main.route("/")
def home():
    return render_template("home.html")


# ----------------------------------------
# Search / Investigation
# ----------------------------------------
@main.route("/search", methods=["GET", "POST"])
@main.route("/username-search", methods=["GET", "POST"])
@main.route("/username", methods=["GET", "POST"])
def search():

    if request.method == "GET":
        # Pass the platform list so search.html can inject it into window.TL_PLATFORMS
        return render_template("search.html", platforms=_PLATFORMS_FOR_JS)

    target = request.form.get("query", "").strip()

    if not target:
        return render_template(
            "search.html",
            platforms=_PLATFORMS_FOR_JS,
            error="Please enter a target.",
        )

    # Run investigation (synchronous — browser awaits while animation plays)
    result = investigate(target)

    if result.get("success"):
        return render_template("results.html", result=result)

    if "data" in result:
        data = result.get("data") or {}
        result.setdefault("candidate", result.get("type", "target"))
        result["reason"] = data.get("error") or result.get("status", "Investigation failed.")
        result["details"] = data.get("details") or data.get("errors") or []
        result["suggestions"] = []

    return render_template("invalid_target.html", validation=result)


# ----------------------------------------
# Override (forced type)
# ----------------------------------------
@main.route("/override", methods=["POST"])
def override():

    target      = request.form.get("target",      "").strip()
    forced_type = request.form.get("forced_type", "").strip()

    if not target or not forced_type:
        return render_template(
            "search.html",
            platforms=_PLATFORMS_FOR_JS,
            error="Invalid override request.",
        )

    result = investigate(target, forced_type=forced_type)

    if not result.get("success") and "data" not in result:
        result.setdefault("candidate", forced_type.title())
        result.setdefault("suggestions", [])
        return render_template("invalid_target.html", validation=result)

    return render_template("results.html", result=result)


# ----------------------------------------
# Email Search
# ----------------------------------------
@main.route("/email-search", methods=["GET", "POST"])
@main.route("/email", methods=["GET", "POST"])
def email_search():

    if request.method == "GET":
        return render_template("email_search.html")

    target = request.form.get("email", "").strip() or request.form.get("query", "").strip()

    if not target:
        return render_template(
            "email_search.html",
            error="Email address is required.",
        )

    result = investigate(target, forced_type="email")

    if result.get("success") and result.get("data", {}).get("success", True):
        return render_template("results.html", result=result)

    error_msg = result.get("data", {}).get("error") or "Invalid email address."
    return render_template("email_search.html", error=error_msg, target=target)


# ----------------------------------------
# Phone Search
# ----------------------------------------
@main.route("/phone-search", methods=["GET", "POST"])
@main.route("/phone", methods=["GET", "POST"])
def phone_search():

    if request.method == "GET":
        return render_template("phone_search.html")

    target = request.form.get("phone", "").strip() or request.form.get("query", "").strip()

    if not target:
        return render_template(
            "phone_search.html",
            error="Phone number is required.",
        )

    result = investigate(target, forced_type="phone")

    if result.get("success") and result.get("data", {}).get("success", True):
        return render_template("results.html", result=result)

    error_msg = result.get("data", {}).get("error") or "Invalid phone number."
    return render_template("phone_search.html", error=error_msg, target=target)


# ----------------------------------------
# Hash Search
# ----------------------------------------
@main.route("/hash-search", methods=["GET", "POST"])
@main.route("/hash", methods=["GET", "POST"])
def hash_search():

    if request.method == "GET":
        return render_template("hash_search.html")

    target = request.form.get("hash", "").strip() or request.form.get("query", "").strip()

    if not target:
        return render_template(
            "hash_search.html",
            error="Hash input is required.",
        )

    result = investigate(target, forced_type="hash")

    if result.get("success") and result.get("data", {}).get("valid", True):
        return render_template("results.html", result=result)

    data = result.get("data", {})
    details = data.get("details", [])
    error_msg = data.get("error") or (details[0] if isinstance(details, list) and details else "Invalid hash input.")
    return render_template("hash_search.html", error=error_msg, target=target)


# ----------------------------------------
# Hash API Endpoint
# ----------------------------------------
@main.route("/api/hash/investigate", methods=["POST"])
def api_hash_investigate():
    data = request.get_json(silent=True) or {}
    raw_hash = data.get("hash") or data.get("query") or request.form.get("hash") or request.form.get("query") or ""

    from app.osint.modules.hash.engine import investigate as hash_investigate
    result = hash_investigate(raw_hash)

    response_payload = {
        "success": result["success"],
        "input": result["input"],
        "normalized": result["normalized"],
        "status": result["status"],
        "possible_types": result["possible_types"],
        "confidence": result["confidence"],
        "length": result["length"],
        "encoding": result["encoding"],
        "hash_type": result["hash_type"],
        "details": result["details"],
        "explanation": result.get("explanation"),
        "matches": result["matches"],
        "identification": result.get("identification", {}),
        "lookup": result.get("lookup", {}),
        "summary": result.get("summary", {}),
        "metadata": result["metadata"]
    }
    status_code = 200 if result["valid"] or result["status"] != "invalid" else 400
    return jsonify(response_payload), status_code
