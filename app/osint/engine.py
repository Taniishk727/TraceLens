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

    "md5": hash.investigate,

    "sha1": hash.investigate,

    "sha224": hash.investigate,

    "sha256": hash.investigate,

    "sha384": hash.investigate,

    "sha512": hash.investigate

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


# ==========================================================
# MAIN ENGINE
# ==========================================================

def investigate(target, forced_type=None):

    target = target.strip()

    # ------------------------------------------------------
    # Manual Override
    # ------------------------------------------------------

    if forced_type is not None:

        module_data = run_module(target, forced_type)

        return {

            "success": True,

            "override": True,

            "target": target,

            "type": forced_type,

            "status": "Completed (Manual Override)",

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

    return {

        "success": True,

        "override": False,

        "target": target,

        "type": target_type,

        "status": "Completed",

        "data": module_data

    }