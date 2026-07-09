import re


def detect_target_type(target):

    target = target.strip()

    # Email
    if re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', target):
        return "email"

    # IPv4
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
        return "ip"

    # Domain
    if re.match(r'^[A-Za-z0-9-]+\.[A-Za-z]{2,}$', target):
        return "domain"

    # Phone Number
    if re.match(r'^\+?\d{10,15}$', target):
        return "phone"

    # SHA256
    if re.match(r'^[A-Fa-f0-9]{64}$', target):
        return "hash"

    # Default
    return "username"