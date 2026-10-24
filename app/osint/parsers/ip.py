"""Local IP address classification and optional reverse DNS lookup."""

import ipaddress
import socket
import time


def investigate(target):
    started = time.perf_counter()
    raw = str(target).strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        return {"success": False, "module": "IP", "target": raw, "status": "invalid", "summary": "Invalid IP address.", "artifacts": [], "errors": [str(exc)], "metadata": {}}

    errors = []
    hostname = None
    try:
        hostname = socket.gethostbyaddr(str(address))[0]
    except OSError as exc:
        errors.append(f"Reverse DNS lookup unavailable: {exc}")

    details = {
        "version": address.version,
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_reserved": address.is_reserved,
        "is_loopback": address.is_loopback,
        "is_multicast": address.is_multicast,
        "reverse_dns": hostname,
    }
    artifacts = [{"type": "ip_address", "value": str(address)}, {"type": "classification", "value": details}]
    if hostname:
        artifacts.append({"type": "hostname", "value": hostname})

    return {
        "success": True,
        "module": "IP Investigation",
        "target": str(address),
        "status": "completed",
        "summary": f"Classified IPv{address.version} address {address}; reverse DNS {'found ' + hostname if hostname else 'returned no hostname'}.",
        "artifacts": artifacts,
        "errors": errors,
        "metadata": {**details, "execution_time_ms": round((time.perf_counter() - started) * 1000, 2)},
    }
