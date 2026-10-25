"""IP address classification, reverse DNS, and public network enrichment."""

import ipaddress
import time
from typing import Any

import dns.exception
import dns.resolver
from app.osint.core.transport.requests_transport import RequestsTransport


dns_timeout = 3.0
transport = RequestsTransport(timeout=dns_timeout)
IPWHOIS_URL = "https://ipwho.is/{}"
IPWHOIS_FIELDS = (
    "ip,success,type,continent,continent_code,country,country_code,region,region_code,"
    "city,latitude,longitude,postal,connection.isp,connection.org,connection.asn,"
    "timezone.id,timezone.utc"
)


def _invalid_result(raw: str, message: str) -> dict[str, Any]:
    return {
        "success": False,
        "module": "IP Investigation",
        "target": raw,
        "status": "invalid",
        "summary": "Invalid IP address.",
        "artifacts": [],
        "errors": [message],
        "metadata": {},
    }


def investigate(target: str) -> dict[str, Any]:
    started = time.perf_counter()
    raw = str(target).strip()
    try:
        address = ipaddress.ip_address(raw)
    except ValueError as exc:
        return _invalid_result(raw, str(exc))

    errors: list[str] = []
    details: dict[str, Any] = {
        "version": address.version,
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_reserved": address.is_reserved,
        "is_loopback": address.is_loopback,
        "is_link_local": address.is_link_local,
        "is_multicast": address.is_multicast,
        "is_unspecified": address.is_unspecified,
        "reverse_dns": None,
        "geolocation": None,
    }
    artifacts: list[dict[str, Any]] = [
        {"type": "ip_address", "value": str(address)},
        {"type": "classification", "value": {key: value for key, value in details.items() if key not in ("reverse_dns", "geolocation")}},
    ]

    resolver = dns.resolver.Resolver()
    resolver.timeout = dns_timeout
    resolver.lifetime = dns_timeout
    try:
        ptr_records = resolver.resolve_address(str(address))
        if ptr_records:
            details["reverse_dns"] = str(ptr_records[0]).rstrip(".")
            artifacts.append({"type": "reverse_dns", "value": details["reverse_dns"]})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as exc:
        errors.append(f"Reverse DNS lookup unavailable: {exc}")

    if address.is_global:
        response = transport.fetch(
            IPWHOIS_URL.format(address),
            params={"fields": IPWHOIS_FIELDS},
            headers={"Accept": "application/json"},
        )
        payload = response.get("json") if response.get("success") else None
        if response.get("status") == 429:
            errors.append("IP geolocation provider rate limit reached (HTTP 429).")
        elif isinstance(payload, dict) and payload.get("success") is True:
            selected = {
                key: payload.get(key)
                for key in ("type", "continent", "continent_code", "country", "country_code", "region", "region_code", "city", "latitude", "longitude", "postal")
                if payload.get(key) is not None
            }
            for group, keys in (("connection", ("isp", "org", "asn")), ("timezone", ("id", "utc"))):
                value = payload.get(group)
                if isinstance(value, dict):
                    selected[group] = {key: value[key] for key in keys if value.get(key) is not None}
            details["geolocation"] = selected
            if selected:
                artifacts.append({"type": "ip_geolocation", "value": selected})
        elif not response.get("success"):
            errors.append(f"IP geolocation lookup unavailable: {response.get('error') or 'network request failed'}")
        else:
            message = payload.get("message") if isinstance(payload, dict) else None
            errors.append(f"IP geolocation lookup unavailable: {message or 'unexpected provider response'}")

    status = "partial" if address.is_global and errors else "completed"
    location = details["geolocation"] or {}
    location_label = ", ".join(str(location[key]) for key in ("city", "region", "country") if location.get(key))
    summary = f"Classified IPv{address.version} address {address}."
    if location_label:
        summary += f" Approximate network location: {location_label}."
    if details["reverse_dns"]:
        summary += f" Reverse DNS: {details['reverse_dns']}."

    return {
        "success": True,
        "module": "IP Investigation",
        "target": str(address),
        "status": status,
        "summary": summary,
        "artifacts": artifacts,
        "errors": errors,
        "metadata": {**details, "execution_time_ms": round((time.perf_counter() - started) * 1000, 2)},
    }
