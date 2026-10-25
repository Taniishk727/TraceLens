"""TraceLens application package.

The Flask dependency and web routes are loaded only when ``create_app`` is
called. Core investigations can therefore be imported by the CLI without
initializing the web application.
"""

__version__ = "0.1.5"


def create_app():
    """Create and configure the Flask web application."""
    from app.config import load_user_config

    load_user_config()
    from flask import Flask

    from app.routes import main
    from app.osint.modules.username.data.validator import validate_sites

    report = validate_sites()
    if not report["valid"]:
        messages = "; ".join(
            f"{error['site']} ({error['type']}): {error['message']}"
            for error in report["errors"]
        )
        raise RuntimeError(f"Username site configuration is invalid: {messages}")

    application = Flask(__name__)
    application.register_blueprint(main)
    return application
