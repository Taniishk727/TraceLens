"""
============================================================
TraceLens PGP Key OSINT Collector
============================================================

Searches public OpenPGP key servers (keys.openpgp.org, keyserver.ubuntu.com)
for published PGP public keys associated with an email address.
Collects Key IDs, fingerprints, creation/expiration dates, and User IDs.

Author:
    TraceLens
"""

import datetime
import logging
import urllib.request
import urllib.parse
import urllib.error
from typing import Any

from app.osint.modules.email.base import BaseCollector
from app.osint.modules.email.validator import EmailValidationResult

logger = logging.getLogger(__name__)

# Public OpenPGP Key Server Endpoints
KEY_SERVERS: list[str] = [
    "https://keyserver.ubuntu.com/pks/lookup?search={email}&op=index&fingerprint=on&options=mr",
    "https://pgp.mit.edu/pks/lookup?search={email}&op=index&fingerprint=on&options=mr",
]


class PGPCollector(BaseCollector):
    """
    OpenPGP Public Key OSINT Collector.
    Queries HKP key servers for public encryption keys matching the email address.
    """

    def __init__(self, timeout: float = 4.0):
        super().__init__(name="PGP Collector", category="Security")
        self.timeout = timeout

    def _parse_timestamp(self, ts_str: str) -> str | None:
        """Converts unix timestamp or raw date string into human-readable ISO date."""
        if not ts_str or not ts_str.isdigit():
            return None
        try:
            dt = datetime.datetime.fromtimestamp(int(ts_str), tz=datetime.timezone.utc)
            return dt.strftime("%Y-%m-%d")
        except Exception:
            return ts_str

    def search_hkp_server(self, server_url_fmt: str, email: str) -> list[dict[str, Any]]:
        """
        Queries an HKP machine-readable (op=index&options=mr) key server endpoint.
        Parses `pub:`, `fpr:`, and `uid:` lines.
        """
        encoded_email = urllib.parse.quote(email)
        url = server_url_fmt.format(email=encoded_email)
        keys: list[dict[str, Any]] = []

        req = urllib.request.Request(
            url,
            headers={"User-Agent": "TraceLens OSINT Engine/1.0 (Security Research)"},
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status != 200:
                    return []
                content = resp.read().decode("utf-8", errors="ignore")

                current_key: dict[str, Any] | None = None

                for line in content.splitlines():
                    line = line.strip()
                    if not line or ":" not in line:
                        continue

                    parts = line.split(":")
                    record_type = parts[0]

                    if record_type == "pub":
                        if current_key:
                            keys.append(current_key)

                        key_id = parts[1] if len(parts) > 1 else ""
                        created_raw = parts[4] if len(parts) > 4 else ""
                        expires_raw = parts[5] if len(parts) > 5 else ""

                        created_date = self._parse_timestamp(created_raw)
                        expiry_date = self._parse_timestamp(expires_raw) or ("Never" if not expires_raw else expires_raw)

                        current_key = {
                            "key_id": f"0x{key_id}" if key_id and not key_id.startswith("0x") else key_id,
                            "fingerprint": "",
                            "created_date": created_date or "Unknown",
                            "expiry_date": expiry_date,
                            "user_ids": [],
                            "email_matches": [],
                        }

                    elif record_type == "fpr" and current_key:
                        fpr = parts[1] if len(parts) > 1 else ""
                        current_key["fingerprint"] = fpr

                    elif record_type == "uid" and current_key:
                        raw_uid = parts[1] if len(parts) > 1 else ""
                        decoded_uid = urllib.parse.unquote(raw_uid)
                        current_key["user_ids"].append(decoded_uid)
                        if email.lower() in decoded_uid.lower():
                            current_key["email_matches"].append(decoded_uid)

                if current_key:
                    keys.append(current_key)

        except urllib.error.HTTPError as err:
            logger.debug("[PGP] HKP lookup returned status %d for %s", err.code, email)
        except Exception as exc:
            logger.debug("[PGP] HKP lookup error for %s: %s", email, exc)

        return keys

    def search_keys_openpgp(self, email: str) -> list[dict[str, Any]]:
        """
        Queries keys.openpgp.org REST API for key existence.
        """
        url = f"https://keys.openpgp.org/vks/v1/by-email/{urllib.parse.quote(email)}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "TraceLens OSINT Engine/1.0 (Security Research)"},
        )
        keys: list[dict[str, Any]] = []

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    armor_key = resp.read().decode("utf-8", errors="ignore")
                    if "BEGIN PGP PUBLIC KEY BLOCK" in armor_key:
                        keys.append({
                            "key_id": "keys.openpgp.org Key",
                            "fingerprint": "Verified on keys.openpgp.org",
                            "created_date": "Active",
                            "expiry_date": "Active",
                            "user_ids": [email],
                            "email_matches": [email],
                        })
        except Exception:
            pass

        return keys

    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes PGP key server lookups.
        """
        email = validation.email
        logger.info("[PGP] Searching public PGP key servers for %s", email)

        all_keys: list[dict[str, Any]] = []

        # 1. Search HKP key servers
        for server_fmt in KEY_SERVERS:
            keys = self.search_hkp_server(server_fmt, email)
            if keys:
                all_keys.extend(keys)
                break

        # 2. Search keys.openpgp.org if HKP returned nothing
        if not all_keys:
            openpgp_keys = self.search_keys_openpgp(email)
            if openpgp_keys:
                all_keys.extend(openpgp_keys)

        if all_keys:
            logger.info("[PGP] Found %d PGP key(s) for %s", len(all_keys), email)
            return {
                "collector": self.name,
                "status": "completed",
                "keys_found": len(all_keys),
                "keys": all_keys,
                "reason": f"Discovered {len(all_keys)} public PGP key(s) registered for target email.",
            }

        logger.info("[PGP] No PGP keys found for %s", email)
        return {
            "collector": self.name,
            "status": "not_found",
            "keys_found": 0,
            "keys": [],
            "reason": "No public PGP keys found on key servers.",
        }
