
"""
============================================================
TraceLens Application Factory
============================================================

Initializes the Flask application and validates the OSINT
framework before the server starts.

Author:
TraceLens
"""

from flask import Flask

from app.routes import main

from app.osint.data.validator import validate_sites


# ==========================================================
# APPLICATION FACTORY
# ==========================================================

def create_app():

    app = Flask(__name__)

    # ------------------------------------------------------
    # Register Blueprints
    # ------------------------------------------------------

    app.register_blueprint(main)

    # ------------------------------------------------------
    # Validate Username Site Database
    # ------------------------------------------------------

    report = validate_sites()

    print("\n")

    print("=" * 60)
    print("TraceLens OSINT Engine")
    print("=" * 60)

    print(f"Loaded Sites        : {report['total_sites']}")
    print(f"Registered Detectors: {report['registered_detectors']}")

    if report["valid"]:

        print("Validation          : PASSED")

    else:

        print("Validation          : FAILED")

        print()

        for error in report["errors"]:

            print(
                f"[ERROR] "
                f"{error['site']} | "
                f"{error['type']} | "
                f"{error['message']}"
            )

        for warning in report["warnings"]:

            print(
                f"[WARNING] "
                f"{warning['site']} | "
                f"{warning['message']}"
            )

        print("=" * 60)

        raise RuntimeError(
            "TraceLens failed to start because the "
            "Username Site Database contains errors."
        )

    print("=" * 60)

    print("✓ TraceLens initialized successfully.\n")

    return app