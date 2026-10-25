"""Shared user configuration for the web app and CLI."""

import json
import os
from pathlib import Path
from typing import Any


SUPPORTED_SETTINGS = {"HIBP_API_KEY", "VIRUSTOTAL_API_KEY"}


def config_path() -> Path:
    """Return the user config path, honoring an explicit override."""
    override = os.environ.get("TRACELENS_CONFIG")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "tracelens" / "config.json"


def load_user_config() -> dict[str, Any]:
    """Load supported values without overriding environment variables."""
    path = config_path()
    if not path.is_file():
        return {}
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read TraceLens config at {path}: {exc}") from exc
    if not isinstance(values, dict):
        raise ValueError(f"TraceLens config at {path} must contain a JSON object.")

    loaded = {}
    for key in SUPPORTED_SETTINGS:
        value = values.get(key)
        if value is not None and str(value).strip():
            if not os.environ.get(key):
                os.environ[key] = str(value).strip()
            loaded[key] = os.environ[key]
    return loaded
