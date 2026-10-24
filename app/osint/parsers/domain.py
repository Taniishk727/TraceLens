"""Basic domain intelligence based on the system resolver."""

import socket
import time


def investigate(target):
    started = time.perf_counter()
    domain = str(target).strip().rstrip(".").lower()
    if not domain or len(domain) > 253:
        return {"success": False, "module": "Domain", "target": domain, "status": "invalid", "summary": "Invalid domain name.", "artifacts": [], "errors": ["Domain must contain between 1 and 253 characters."], "metadata": {}}

    try:
        records = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
        addresses = sorted({record[4][0] for record in records})
        errors = []
    except (OSError, UnicodeError) as exc:
        addresses = []
        errors = [f"System DNS lookup failed: {exc}"]

    return {
        "success": True,
        "module": "Domain Investigation",
        "target": domain,
        "status": "completed" if addresses else "partial",
        "summary": f"Resolved {len(addresses)} IP address(es) for {domain}." if addresses else f"No IP addresses were resolved for {domain}.",
        "artifacts": [{"type": "ip_address", "value": address} for address in addresses],
        "errors": errors,
        "metadata": {"address_count": len(addresses), "execution_time_ms": round((time.perf_counter() - started) * 1000, 2)},
    }
