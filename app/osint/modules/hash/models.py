"""
============================================================
TraceLens Hash Module - Data Models
============================================================

Defines structured result schemas and data containers for hash input
validation, algorithm detection, and investigation payloads.

Author:
    TraceLens
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional


class DetectionConfidence(str, Enum):
    """Confidence levels for hash algorithm detection."""
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


class DetectionStatus(str, Enum):
    """Investigation status codes for hash targets."""
    IDENTIFIED = "identified"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"
    INVALID = "invalid"


@dataclass
class HashValidationResult:
    """Holds results of hash input validation."""
    valid: bool
    input: str
    normalized: str = ""
    error: Optional[str] = None
    details: List[str] = field(default_factory=list)
    length: int = 0
    encoding: str = "unknown"
    is_structured: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "input": self.input,
            "normalized": self.normalized,
            "error": self.error,
            "details": self.details,
            "length": self.length,
            "encoding": self.encoding,
            "is_structured": self.is_structured,
        }


@dataclass
class HashAlgorithmMatch:
    """Represents a candidate algorithm match."""
    name: str
    category: str
    confidence: DetectionConfidence
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence.value,
            "description": self.description,
        }


@dataclass
class HashDetectionResult:
    """Holds identification output from the HashDetector."""
    status: DetectionStatus
    confidence: DetectionConfidence
    primary_type: str
    possible_types: List[str]
    length: int
    encoding: str
    details: List[str] = field(default_factory=list)
    matches: List[HashAlgorithmMatch] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": self.confidence.value,
            "hash_type": self.primary_type,
            "possible_types": self.possible_types,
            "length": self.length,
            "encoding": self.encoding,
            "details": self.details,
            "matches": [m.to_dict() for m in self.matches],
        }
