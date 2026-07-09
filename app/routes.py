from flask import Blueprint, render_template, request

from app.osint.engine import investigate

main = Blueprint("main", __name__)


# -----------------------------
# Home Page
# -----------------------------
@main.route("/")
def home():
    return render_template("home.html")


# -----------------------------
# New Investigation
# -----------------------------
@main.route("/search", methods=["GET", "POST"])
def search():

    if request.method == "POST":

        target = request.form.get("query", "").strip()

        if not target:
            return render_template(
                "search.html",
                error="Please enter a target."
            )

        # Send the target to the Investigation Engine
        data = investigate(target)

        # Render the appropriate results page
        return render_template(
            "results.html",
            data=data
        )

    return render_template("search.html")