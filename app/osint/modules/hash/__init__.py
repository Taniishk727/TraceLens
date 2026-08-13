"""
============================================================
TraceLens Hash Module
============================================================

Provides hash validation, deterministic identification, and algorithm
ambiguity resolution for the TraceLens OSINT engine.

Author:
    TraceLens
"""

from app.osint.modules.hash.engine import HashEngine, investigate
from app.osint.modules.hash.validator import HashValidator
from app.osint.modules.hash.detector import HashDetector
from app.osint.modules.hash.models import (
    HashValidationResult,
    HashDetectionResult,
    DetectionConfidence,
    DetectionStatus,
)

__all__ = [
    "HashEngine",
    "investigate",
    "HashValidator",
    "HashDetector",
    "HashValidationResult",
    "HashDetectionResult",
    "DetectionConfidence",
    "DetectionStatus",
]
