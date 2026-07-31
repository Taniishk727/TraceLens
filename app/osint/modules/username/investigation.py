import re
import ipaddress


# ==========================================================
# EMAIL VALIDATION
# ==========================================================

def is_valid_email(target):

    pattern = (
        r'^[A-Za-z0-9._%+-]+'
        r'@[A-Za-z0-9-]+'
        r'(\.[A-Za-z0-9-]+)+$'
    )

    return re.fullmatch(pattern, target) is not None


# ==========================================================
# IPV4 VALIDATION
# ==========================================================

def validate_ip(target):

    parts = target.split(".")

    if len(parts) != 4:
        return {
            "valid": False,
            "candidate": "ip",
            "reason": "IPv4 address must contain exactly 4 octets.",
            "details": [
                f"Found {len(parts)} octets."
            ],
            "suggestions": ["username", "domain"]
        }

    try:

        ipaddress.IPv4Address(target)

        return {
            "valid": True,
            "type": "ip"
        }

    except ValueError:

        return {
            "valid": False,
            "candidate": "ip",
            "reason": "Invalid IPv4 address.",
            "details": [
                "Each octet must be between 0 and 255."
            ],
            "suggestions": ["username", "domain"]
        }


# ==========================================================
# DOMAIN VALIDATION
# ==========================================================

def validate_domain(target):

    pattern = (
        r'^(?!-)(?:[A-Za-z0-9-]{1,63}\.)+'
        r'[A-Za-z]{2,63}$'
    )

    if re.fullmatch(pattern, target):

        return {
            "valid": True,
            "type": "domain"
        }

    return {
        "valid": False,
        "candidate": "domain",
        "reason": "Invalid domain name.",
        "details": [
            "Domain format is incorrect."
        ],
        "suggestions": ["username"]
    }


# ==========================================================
# PHONE VALIDATION
# ==========================================================

def validate_phone(target):

    if len(target) != 10:

        return {
            "valid": False,
            "candidate": "phone",
            "reason": "Phone number must contain exactly 10 digits.",
            "details": [
                f"Found {len(target)} digits."
            ],
            "suggestions": ["username"]
        }

    if not re.fullmatch(r'[6-9]\d{9}', target):

        return {
            "valid": False,
            "candidate": "phone",
            "reason": "Invalid Indian phone number.",
            "details": [
                "Phone number must begin with digits 6–9."
            ],
            "suggestions": ["username"]
        }

    return {
        "valid": True,
        "type": "phone"
    }


# ==========================================================
# HASH DETECTION
# ==========================================================

def validate_hash(target):

    if not re.fullmatch(r'[A-Fa-f0-9]+', target):
        return None

    hashes = {

        32: "md5",

        40: "sha1",

        56: "sha224",

        64: "sha256",

        96: "sha384",

        128: "sha512"

    }

    if len(target) in hashes:

        return {
            "valid": True,
            "type": hashes[len(target)]
        }

    return {
        "valid": False,
        "candidate": "hash",
        "reason": "Unknown hash length.",
        "details": [
            f"Length = {len(target)}"
        ],
        "suggestions": ["username"]
    }


# ==========================================================
# USERNAME VALIDATION
# ==========================================================

def validate_username(target):

    if len(target) < 3:

        return {
            "valid": False,
            "candidate": "username",
            "reason": "Username is too short.",
            "details": [],
            "suggestions": []
        }

    if len(target) > 30:

        return {
            "valid": False,
            "candidate": "username",
            "reason": "Username exceeds 30 characters.",
            "details": [],
            "suggestions": []
        }

    if not re.fullmatch(r'^[A-Za-z0-9._-]+$', target):

        return {
            "valid": False,
            "candidate": "username",
            "reason": "Username contains invalid characters.",
            "details": [],
            "suggestions": []
        }

    return {
        "valid": True,
        "type": "username"
    }


# ==========================================================
# CANDIDATE DETECTION
# ==========================================================

def identify_candidate(target):

    if "@" in target:
        return "email"

    if target.count(".") >= 3:
        return "ip"

    if target.isdigit():
        return "phone"

    if "." in target:
        return "domain"

    if re.fullmatch(r'[A-Fa-f0-9]+', target):
        return "hash"

    return "username"


# ==========================================================
# MAIN DETECTOR
# ==========================================================

def detect_target(target):

    target = target.strip()

    candidate = identify_candidate(target)

    if candidate == "email":

        if is_valid_email(target):

            return {
                "valid": True,
                "type": "email"
            }

        return {
            "valid": False,
            "candidate": "email",
            "reason": "Invalid email address.",
            "details": [
                "Email format is incorrect."
            ],
            "suggestions": ["username"]
        }

    if candidate == "ip":
        return validate_ip(target)

    if candidate == "domain":
        return validate_domain(target)

    if candidate == "phone":
        return validate_phone(target)

    if candidate == "hash":
        return validate_hash(target)

    return validate_username(target)

def detect_target_type(target):
    """
    Temporary compatibility wrapper.
    Will be removed after engine.py is updated.
    """
    result = detect_target(target)

    if result["valid"]:
        return result["type"]

    return "invalid"