"""
============================================================
TraceLens Hash Module - Detector Engine
============================================================

Performs deterministic algorithm identification against candidate hashes.
Ensures zero false certainty by correctly identifying ambiguous hash
lengths and categorizing confidence states into:
- CONFIRMED
- LIKELY
- AMBIGUOUS
- UNKNOWN

Author:
    TraceLens
"""

from typing import List
from app.osint.modules.hash.models import (
    DetectionConfidence,
    DetectionStatus,
    HashAlgorithmMatch,
    HashDetectionResult,
    HashValidationResult,
)
from app.osint.modules.hash.signatures import ALGORITHM_DEFINITIONS


class HashDetector:
    """
    Detector engine for identifying potential hash algorithms from validated input.
    """

    @classmethod
    def detect(cls, validation: HashValidationResult) -> HashDetectionResult:
        """
        Detects possible hash algorithms for a validated hash input.

        Args:
            validation: HashValidationResult from HashValidator.

        Returns:
            HashDetectionResult containing identified candidate types and confidence.
        """
        if not validation.valid:
            return HashDetectionResult(
                status=DetectionStatus.INVALID,
                confidence=DetectionConfidence.UNKNOWN,
                primary_type="Invalid",
                possible_types=[],
                length=validation.length,
                encoding=validation.encoding,
                details=[validation.error or "Invalid hash input."],
                matches=[],
            )

        target = validation.normalized
        target_len = len(target)

        matching_defs = []

        # 1. First check structured / prefix-based signature definitions
        if validation.is_structured:
            for algo in ALGORITHM_DEFINITIONS:
                if algo["is_structured"] and algo["pattern"].match(target):
                    matching_defs.append(algo)

        # 2. Check standard definitions (hex or base64 length matching)
        if not matching_defs:
            for algo in ALGORITHM_DEFINITIONS:
                if algo["pattern"].match(target):
                    matching_defs.append(algo)

        # 3. Process matches & determine confidence state
        if not matching_defs:
            return HashDetectionResult(
                status=DetectionStatus.UNKNOWN,
                confidence=DetectionConfidence.UNKNOWN,
                primary_type="Unknown",
                possible_types=[],
                length=target_len,
                encoding=validation.encoding,
                details=[f"No matching algorithm registered for length {target_len}."],
                matches=[],
            )

        # Create match objects
        matches: List[HashAlgorithmMatch] = []

        # If exactly 1 structured or unique match exists
        if len(matching_defs) == 1:
            algo = matching_defs[0]
            confidence = (
                DetectionConfidence.CONFIRMED
                if algo["is_structured"]
                else DetectionConfidence.LIKELY
            )
            match_obj = HashAlgorithmMatch(
                name=algo["name"],
                category=algo["category"],
                confidence=confidence,
                description=algo["description"],
            )
            matches.append(match_obj)

            return HashDetectionResult(
                status=DetectionStatus.IDENTIFIED,
                confidence=confidence,
                primary_type=algo["name"],
                possible_types=[algo["name"]],
                length=target_len,
                encoding=algo["encoding"],
                details=[f"Algorithm uniquely identified as {algo['name']}."],
                matches=matches,
            )

        # If multiple candidates share the exact representation (Ambiguous case)
        confidence = DetectionConfidence.AMBIGUOUS
        possible_names = [algo["name"] for algo in matching_defs]

        for algo in matching_defs:
            matches.append(
                HashAlgorithmMatch(
                    name=algo["name"],
                    category=algo["category"],
                    confidence=confidence,
                    description=algo["description"],
                )
            )

        return HashDetectionResult(
            status=DetectionStatus.AMBIGUOUS,
            confidence=confidence,
            primary_type="Ambiguous",
            possible_types=possible_names,
            length=target_len,
            encoding=matching_defs[0]["encoding"],
            details=[
                f"Hash format is ambiguous. Matches {len(possible_names)} potential algorithms: {', '.join(possible_names)}."
            ],
            matches=matches,
        )
