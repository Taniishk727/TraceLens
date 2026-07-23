from flask import Blueprint, render_template, request

from app.osint.engine import investigate
from app.osint.data.username_sites import SITES

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

    if result["success"]:
        return render_template("results.html", result=result)

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

    return render_template("results.html", result=result)