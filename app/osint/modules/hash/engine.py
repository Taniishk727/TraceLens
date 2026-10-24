"""
============================================================
TraceLens Hash Investigation Engine
============================================================

Central coordinator for Hash OSINT investigations.
Orchestrates validation, algorithm identification, ambiguity detection,
public hash lookup, and payload construction.

Execution Flow:
    Raw Hash Input
        ↓
    HashValidator (Trimming, Whitespace, Sanity, Case Normalization)
        ↓
    HashDetector (Signature & Pattern Matching, Confidence Assessment)
        ↓
    LookupRegistry (Automatic Public Hash Lookup Execution)
        ↓
    Execution Time Measurement
        ↓
    Return Standardized Hash OSINT Payload

Author:
    TraceLens
"""

import time
from typing import Any, Dict
from app.osint.modules.hash.validator import HashValidator
from app.osint.modules.hash.detector import HashDetector
from app.osint.modules.hash.lookup.registry import execute_lookup
from app.osint.modules.hash.lookup.models import LookupStatus


class HashEngine:
    """
    Orchestration engine for Hash OSINT investigations.
    """

    def investigate(self, raw_hash: str) -> Dict[str, Any]:
        """
        Main investigation entrypoint for hash targets.

        Args:
            raw_hash: Input hash string to validate, identify, and look up.

        Returns:
            Standardized investigation result dictionary.
        """
        start_time = time.perf_counter()

        # 1. Input Validation
        validation = HashValidator.validate(raw_hash)

        # 2. Algorithm Identification
        detection = HashDetector.detect(validation)

        # 3. Public Hash Lookup Execution (Feature 2)
        if validation.valid and detection.status.value != "unknown":
            lookup_res = execute_lookup(
                validation.normalized, possible_algorithms=detection.possible_types
            )
            lookup_dict = lookup_res.to_dict()
        else:
            lookup_dict = {
                "status": LookupStatus.UNSUPPORTED.value,
                "plaintext": None,
                "source": "None",
                "source_url": None,
                "algorithm": None,
                "details": ["Hash target invalid or algorithm unsupported for lookup."],
                "execution_time_ms": 0.0,
            }

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

        # 4. Assemble Standardized Response Payload
        is_success = validation.valid

        # Standard response payload
        identification_dict = {
            "status": detection.status.value,
            "confidence": detection.confidence.value,
            "hash_type": detection.primary_type,
            "possible_types": detection.possible_types,
            "length": detection.length,
            "encoding": detection.encoding,
            "details": detection.details,
            "explanation": detection.explanation,
            "matches": [m.to_dict() for m in detection.matches],
        }

        has_plaintext = lookup_dict.get("status") == LookupStatus.FOUND.value and lookup_dict.get("plaintext") is not None

        return {
            "success": is_success,
            "module": "Hash Investigation",
            "status": detection.status.value,
            "target": validation.input,
            "input": validation.input,
            "normalized": validation.normalized,
            "valid": validation.valid,
            "hash_type": detection.primary_type,
            "confidence": detection.confidence.value,
            "possible_types": detection.possible_types,
            "length": detection.length,
            "encoding": detection.encoding,
            "details": detection.details or (validation.details if not is_success else []),
            "explanation": detection.explanation,
            "matches": [m.to_dict() for m in detection.matches],
            "identification": identification_dict,
            "lookup": lookup_dict,
            "summary": {
                "input": validation.input,
                "normalized": validation.normalized,
                "status": detection.status.value,
                "confidence": detection.confidence.value,
                "hash_type": detection.primary_type,
                "possible_types": detection.possible_types,
                "length": detection.length,
                "encoding": detection.encoding,
                "lookup_status": lookup_dict.get("status"),
                "plaintext_recovered": has_plaintext,
                "lookup_source": lookup_dict.get("source"),
            },
            "metadata": {
                "execution_time_ms": elapsed_ms,
            },
        }


# Global engine instance
_ENGINE = HashEngine()


def investigate(raw_hash: str) -> Dict[str, Any]:
    """
    Module interface function matching TraceLens investigation dispatcher conventions.
    """
    return _ENGINE.investigate(raw_hash)
