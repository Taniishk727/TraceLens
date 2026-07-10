from flask import Blueprint, render_template, request
from app.osint.engine import investigate

main = Blueprint("main", __name__)


# ----------------------------------------
# Home Page
# ----------------------------------------
@main.route("/")
def home():
    return render_template("home.html")


# ----------------------------------------
# New Investigation
# ----------------------------------------
from flask import Blueprint, render_template, request

from app.osint.engine import investigate

main = Blueprint("main", __name__)


@main.route("/")
def home():
    return render_template("home.html")


@main.route("/search", methods=["GET", "POST"])
def search():

    if request.method == "GET":
        return render_template("search.html")

    target = request.form.get("query", "").strip()

    if not target:

        return render_template(
            "search.html",
            error="Please enter a target."
        )

    # Run Investigation
    result = investigate(target)

    # ------------------------------------
    # Investigation Successful
    # ------------------------------------

    if result["success"]:

        return render_template(
            "results.html",
            result=result
        )

    # ------------------------------------
    # Validation Failed
    # ------------------------------------

    return render_template(
        "invalid_target.html",
        validation=result
    )
@main.route("/override", methods=["POST"])
def override():

    target = request.form.get("target", "").strip()
    forced_type = request.form.get("forced_type", "").strip()

    if not target or not forced_type:

        return render_template(
            "search.html",
            error="Invalid override request."
        )

    result = investigate(
        target,
        forced_type=forced_type
    )

    return render_template(
        "results.html",
        result=result
    )