"""Domain validation and baseline DNS reconnaissance."""

from concurrent.futures import ThreadPoolExecutor
import re
import time
from typing import Any

import dns.exception
import dns.resolver


dns_timeout = 3.0
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA")


def normalize_domain_name(value: str) -> str:
    """Return a validated ASCII/IDNA domain, raising ValueError for invalid input."""
    raw = str(value).strip()
    if raw.endswith("."):
        raw = raw[:-1]
    if not raw or len(raw) > 253 or any(char in raw for char in ("/", "\\", ":", "@", "?", "#")):
        raise ValueError("Enter a domain name without a scheme, path, port, or credentials.")
    try:
        domain = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Domain contains an invalid internationalized label.") from exc
    labels = domain.split(".")
    if len(labels) < 2 or any(
        len(label) > 63
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    ):
        raise ValueError("Domain labels must be 1–63 characters, separated by dots, and cannot start or end with a hyphen.")
    if len(labels[-1]) < 2 or not re.fullmatch(r"[a-z](?:[a-z0-9-]*[a-z0-9])?", labels[-1]):
        raise ValueError("Domain must have a valid top-level domain label.")
    return domain


def _record_value(record_type: str, record: Any) -> Any:
    if record_type in ("A", "AAAA"):
        return str(record.address)
    if record_type == "MX":
        return {"preference": int(record.preference), "exchange": str(record.exchange).rstrip(".").lower()}
    if record_type == "NS":
        return str(record.target).rstrip(".").lower()
    if record_type == "TXT":
        return b"".join(record.strings).decode("utf-8", errors="replace")
    if record_type == "CAA":
        value = record.value
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return {"flags": int(record.flags), "tag": str(record.tag), "value": str(value)}
    if record_type == "SOA":
        return {
            "primary_name_server": str(record.mname).rstrip(".").lower(),
            "responsible_party": str(record.rname).rstrip(".").lower(),
            "serial": int(record.serial),
            "refresh": int(record.refresh),
            "retry": int(record.retry),
            "expire": int(record.expire),
            "minimum_ttl": int(record.minimum),
        }
    return str(record)


def _query_records(domain: str, record_type: str) -> tuple[list[Any], str | None]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = dns_timeout
    resolver.lifetime = dns_timeout
    try:
        answer = resolver.resolve(domain, record_type, raise_on_no_answer=False)
        if answer.rrset is None:
            return [], None
        return [_record_value(record_type, record) for record in answer], None
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return [], None
    except dns.exception.Timeout:
        return [], f"{record_type} lookup timed out."
    except dns.resolver.NoNameservers:
        return [], f"No DNS nameserver returned a {record_type} answer."
    except (OSError, UnicodeError, dns.exception.DNSException) as exc:
        return [], f"{record_type} lookup failed: {exc}"


def investigate(target: str) -> dict[str, Any]:
    started = time.perf_counter()
    raw = str(target).strip()
    try:
        domain = normalize_domain_name(raw)
    except ValueError as exc:
        return {
            "success": False,
            "module": "Domain Investigation",
            "target": raw,
            "status": "invalid",
            "summary": "Invalid domain name.",
            "artifacts": [],
            "errors": [str(exc)],
            "metadata": {},
        }

    queries = [(domain, record_type) for record_type in RECORD_TYPES]
    queries.append((f"_dmarc.{domain}", "TXT"))
    with ThreadPoolExecutor(max_workers=len(queries)) as pool:
        query_results = list(pool.map(lambda query: _query_records(*query), queries))

    records: dict[str, list[Any]] = {}
    errors: list[str] = []
    for record_type, (values, error) in zip(RECORD_TYPES, query_results[:len(RECORD_TYPES)]):
        records[record_type.lower()] = values
        if error:
            errors.append(error)

    txt_records = records["txt"]
    spf = next((record for record in txt_records if record.lower().startswith("v=spf1")), None)
    dmarc_records, dmarc_error = query_results[-1]
    if dmarc_error:
        errors.append(f"DMARC {dmarc_error.lower()}")
    dmarc = next((record for record in dmarc_records if record.lower().startswith("v=dmarc1")), None)
    records["dmarc"] = dmarc_records

    records["mx"].sort(key=lambda item: item["preference"])
    artifacts: list[dict[str, Any]] = [{"type": "domain", "value": domain}]
    for record_type in RECORD_TYPES:
        for value in records[record_type.lower()]:
            artifacts.append({"type": f"dns_{record_type.lower()}", "value": value})
    if spf:
        artifacts.append({"type": "spf", "value": spf})
    if dmarc:
        artifacts.append({"type": "dmarc", "value": dmarc})

    address_count = len(records["a"]) + len(records["aaaa"])
    record_count = sum(len(records[record_type.lower()]) for record_type in RECORD_TYPES) + len(dmarc_records)
    status = "completed" if record_count and not errors else "partial"
    summary = f"Resolved {record_count} DNS record(s) for {domain}, including {address_count} IP address(es)."
    if not record_count:
        summary = f"No DNS records were returned for {domain}."

    return {
        "success": True,
        "module": "Domain Investigation",
        "target": domain,
        "status": status,
        "summary": summary,
        "artifacts": artifacts,
        "errors": errors,
        "details": {
            "a": records["a"],
            "aaaa": records["aaaa"],
            "mx": records["mx"],
            "ns": records["ns"],
            "txt": txt_records,
            "spf": spf,
            "dmarc": dmarc,
            "caa": records["caa"],
            "soa": records["soa"],
        },
        "metadata": {
            "record_count": record_count,
            "address_count": address_count,
            "execution_time_ms": round((time.perf_counter() - started) * 1000, 2),
        },
    }
