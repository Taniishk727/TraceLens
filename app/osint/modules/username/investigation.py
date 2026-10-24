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
    try:
        ipaddress.ip_address(target)

        return {
            "valid": True,
            "type": "ip"
        }

    except ValueError:

        return {
            "valid": False,
            "candidate": "ip",
            "reason": "Invalid IP address.",
            "details": [
                "Enter a valid IPv4 or IPv6 address."
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
    from app.osint.modules.phone.validator import PhoneValidator, InvalidPhoneError

    try:
        PhoneValidator.validate(target)
        return {"valid": True, "type": "phone"}
    except InvalidPhoneError as exc:
        digits = re.sub(r"\D", "", target)
        return {
            "valid": False,
            "candidate": "phone",
            "reason": str(exc),
            "details": [f"Found {len(digits)} digits."],
            "suggestions": ["username"],
        }


# ==========================================================
# HASH DETECTION
# ==========================================================

def validate_hash(target):
    from app.osint.modules.hash.validator import HashValidator
    from app.osint.modules.hash.detector import HashDetector

    val = HashValidator.validate(target)
    if not val.valid:
        return {
            "valid": False,
            "candidate": "hash",
            "reason": val.error or "Invalid hash input.",
            "details": val.details,
            "suggestions": ["username"]
        }

    det = HashDetector.detect(val)
    if det.status.value == "unknown":
        return {
            "valid": False,
            "candidate": "hash",
            "reason": "Unknown hash length or format.",
            "details": [f"Length = {val.length}"],
            "suggestions": ["username"]
        }

    return {
        "valid": True,
        "type": "hash"
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

    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        pass

    if target.count(".") == 3 and all(part.isdigit() for part in target.split(".")):
        return "ip"

    if re.fullmatch(r"\+?[\d\s().-]+", target) and 7 <= len(re.sub(r"\D", "", target)) <= 15:
        return "phone"

    if "." in target:
        return "domain"

    if target.startswith(("$2", "$argon2", "$1$", "$5$", "$6$", "$apr1$", "$P$", "$H$", "*")):
        return "hash"

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
