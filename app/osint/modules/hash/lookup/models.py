"""
============================================================
TraceLens Hash Lookup - Models & Data Structures
============================================================

Defines lookup status codes, source capability models, and
structured result schemas for public hash lookup operations.

Author:
    TraceLens
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional


class LookupStatus(str, Enum):
    """Result status codes for public hash lookup operations."""
    FOUND = "found"
    NOT_FOUND = "not_found"
    UNSUPPORTED = "unsupported"
    RATE_LIMITED = "rate_limited"
    SOURCE_UNAVAILABLE = "source_unavailable"
    ERROR = "error"


@dataclass
class LookupSourceCapability:
    """Capability definition for a public hash lookup source."""
    name: str
    slug: str
    supported_algorithms: List[str]
    documentation_url: str
    supports_batch: bool = False
    supports_plaintext_lookup: bool = True
    is_active: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "slug": self.slug,
            "supported_algorithms": self.supported_algorithms,
            "documentation_url": self.documentation_url,
            "supports_batch": self.supports_batch,
            "supports_plaintext_lookup": self.supports_plaintext_lookup,
            "is_active": self.is_active,
        }


@dataclass
class LookupResult:
    """Container holding the output of a public hash lookup operation."""
    status: LookupStatus
    plaintext: Optional[str] = None
    source: str = "Unknown"
    source_url: Optional[str] = None
    algorithm: Optional[str] = None
    details: List[str] = field(default_factory=list)
    execution_time_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "plaintext": self.plaintext,
            "source": self.source,
            "source_url": self.source_url,
            "algorithm": self.algorithm,
            "details": self.details,
            "execution_time_ms": self.execution_time_ms,
            "metadata": self.metadata,
        }
