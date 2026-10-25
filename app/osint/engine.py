"""
============================================================
TraceLens Investigation Engine
============================================================

This module is the central dispatcher for every investigation.

Responsibilities
----------------
1. Validate target (automatic mode)
2. Allow manual override (forced_type)
3. Dispatch to the appropriate OSINT module
4. Return a standardized response

"""
# from transport.requests_transport import RequestsTransport
# from transport.browser_transport import BrowserTransport
import uuid

from app.osint.modules.username.investigation import detect_target
from app.osint.modules.username import username
from app.osint.modules.email import engine as email
from app.osint.modules.phone import engine as phone_mod
from app.osint.parsers import (
    domain,
    ip,
    hash
)
# REQUESTS_TRANSPORT = RequestsTransport()
# BROWSER_TRANSPORT = BrowserTransport()
MODULE_REGISTRY = {

    "username": username.investigate,

    "email": email.investigate,

    "domain": domain.investigate,

    "ip": ip.investigate,

    "phone": phone_mod.investigate,

    "hash": hash.investigate,

    "md5": hash.investigate,

    "sha1": hash.investigate,

    "sha224": hash.investigate,

    "sha256": hash.investigate,

    "sha384": hash.investigate,

    "sha512": hash.investigate,

    "bcrypt": hash.investigate,

    "argon2": hash.investigate,

}



# ==========================================================
# MODULE DISPATCHER
# ==========================================================

def run_module(target, target_type):
    """
    Dispatches the investigation to the appropriate module.
    """

    module = MODULE_REGISTRY.get(target_type)

    if module is None:

        return {
            "module": "Unknown",
            "message": f"No investigation module registered for '{target_type}'."
        }

    return module(target)


def configure_timeout(timeout_seconds):
    """Apply a CLI timeout override to network collectors where supported.

    System DNS calls may still use the operating system's resolver timeout.
    """
    timeout_seconds = float(timeout_seconds)
    if timeout_seconds <= 0:
        raise ValueError("Timeout must be greater than zero.")

    from app.osint.modules.hash.lookup.registry import _LOOKUP_REGISTRY

    roots = [
        username.REQUESTS_TRANSPORT,
        username.BROWSER_TRANSPORT,
        email._ENGINE,
        phone_mod._ENGINE,
        _LOOKUP_REGISTRY,
        domain,
        ip,
    ]
    pending = list(roots)
    seen = set()
    child_attributes = ("_collectors", "_sources", "providers", "provider", "transport", "_transport")
    while pending:
        item = pending.pop()
        if item is None or id(item) in seen:
            continue
        seen.add(id(item))
        for attribute in ("timeout", "dns_timeout", "smtp_timeout"):
            if attribute == "timeout" and hasattr(item, "max_timeout"):
                continue  # BrowserTransport uses milliseconds and has a separate cap.
            value = getattr(item, attribute, None)
            if isinstance(value, (int, float)):
                setattr(item, attribute, timeout_seconds)
        set_timeout = getattr(item, "set_timeout", None)
        if callable(set_timeout):
            set_timeout(timeout_seconds)
        for attribute in child_attributes:
            child = getattr(item, attribute, None)
            if isinstance(child, (list, tuple, set)):
                pending.extend(child)
            elif child is not None:
                pending.append(child)


# ==========================================================
# MAIN ENGINE
# ==========================================================

def investigate(target, forced_type=None):

    if not isinstance(target, str):
        target = "" if target is None else str(target)
    target = target.strip()

    if not target:
        return {"success": False, "target": target, "reason": "Target cannot be empty.", "details": ["Enter a target to investigate."], "suggestions": []}

    # ------------------------------------------------------
    # Manual Override
    # ------------------------------------------------------

    if forced_type is not None:

        forced_type = str(forced_type).strip().lower()
        if forced_type not in MODULE_REGISTRY:
            return {
                "success": False,
                "override": True,
                "target": target,
                "type": forced_type,
                "reason": f"Unsupported investigation type: {forced_type}.",
                "details": [f"Supported types: {', '.join(sorted(MODULE_REGISTRY))}."],
                "suggestions": [],
            }

        module_data = run_module(target, forced_type)
        module_success = not isinstance(module_data, dict) or module_data.get("success", True) is not False

        return {

            "success": module_success,

            "investigation_id": uuid.uuid4().hex[:10].upper(),

            "override": True,

            "target": target,

            "type": forced_type,

            "status": "Completed (Manual Override)" if module_success else "Investigation Failed",

            "data": module_data

        }

    # ------------------------------------------------------
    # Automatic Detection
    # ------------------------------------------------------

    detection = detect_target(target)

    # ------------------------------------------------------
    # Validation Failed
    # ------------------------------------------------------

    if not detection["valid"]:

        return {

            "success": False,

            "target": target,

            "candidate": detection["candidate"],

            "reason": detection["reason"],

            "details": detection["details"],

            "suggestions": detection["suggestions"]

        }

    # ------------------------------------------------------
    # Valid Target
    # ------------------------------------------------------

    target_type = detection["type"]

    module_data = run_module(target, target_type)
    module_success = not isinstance(module_data, dict) or module_data.get("success", True) is not False

    return {

        "success": module_success,

        "investigation_id": uuid.uuid4().hex[:10].upper(),

        "override": False,

        "target": target,

        "type": target_type,

        "status": "Completed" if module_success else "Investigation Failed",

        "data": module_data

    }
