"""
============================================================
TraceLens Hash Lookup - Source Registry & Manager
============================================================

Manages registration and orchestration of public hash lookup sources.

Author:
    TraceLens
"""

import logging
import time
from typing import List, Optional
from app.osint.modules.hash.lookup.base import BaseLookupSource
from app.osint.modules.hash.lookup.models import LookupResult, LookupStatus
from app.osint.modules.hash.lookup.sources.hashtoolkit import HashToolkitSource
from app.osint.modules.hash.lookup.sources.crackstation import CrackStationSource
from app.osint.modules.hash.lookup.sources.circl_hashlookup import CIRCLHashlookupSource
from app.osint.modules.hash.lookup.sources.virustotal import VirusTotalSource

logger = logging.getLogger(__name__)


class LookupRegistry:
    """
    Registry for managing and executing public hash lookup sources.
    """

    def __init__(self):
        self._sources: List[BaseLookupSource] = []
        # Register default lookup sources
        self.register_source(HashToolkitSource())
        self.register_source(CrackStationSource())
        self.register_source(CIRCLHashlookupSource())
        self.register_source(VirusTotalSource())

    def register_source(self, source: BaseLookupSource) -> None:
        """Registers a new lookup source into the engine pipeline."""
        if not isinstance(source, BaseLookupSource):
            raise TypeError("Source must inherit from BaseLookupSource.")
        self._sources.append(source)

    def get_sources(self) -> List[BaseLookupSource]:
        """Returns all registered lookup sources."""
        return list(self._sources)

    def execute_lookup(
        self, hash_value: str, possible_algorithms: Optional[List[str]] = None
    ) -> LookupResult:
        """
        Queries active public lookup sources sequentially for an exact match.

        Args:
            hash_value: Normalized hash string.
            possible_algorithms: Candidate algorithm list from Feature 1 identification.

        Returns:
            LookupResult detailing match state and plaintext payload.
        """
        start_time = time.perf_counter()
        active_sources = [s for s in self._sources if s.capability.is_active]

        if not active_sources:
            elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return LookupResult(
                status=LookupStatus.SOURCE_UNAVAILABLE,
                source="TraceLens Engine",
                details=["No active public hash lookup sources configured."],
                execution_time_ms=elapsed_ms,
            )

        last_result: Optional[LookupResult] = None
        database_matches: list[LookupResult] = []

        for source in active_sources:
            try:
                res = source.lookup(hash_value, possible_algorithms=possible_algorithms)
                if res.status == LookupStatus.FOUND:
                    if res.plaintext is not None:
                        if database_matches:
                            res.metadata["database_matches"] = [
                                {"source": item.source, "algorithm": item.algorithm, "metadata": item.metadata}
                                for item in database_matches
                            ]
                        return res
                    database_matches.append(res)
                    continue
                last_result = res
            except Exception as exc:
                logger.error("[LookupRegistry] Source %s error: %s", source.capability.name, exc)
                last_result = LookupResult(
                    status=LookupStatus.ERROR,
                    source=source.capability.name,
                    source_url=source.capability.documentation_url,
                    details=[f"Error executing lookup: {str(exc)}"],
                )

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        if database_matches:
            return LookupResult(
                status=LookupStatus.FOUND,
                source=" / ".join(item.source for item in database_matches),
                source_url=database_matches[0].source_url,
                algorithm=database_matches[0].algorithm,
                details=[detail for item in database_matches for detail in item.details],
                execution_time_ms=elapsed_ms,
                metadata={"database_matches": [
                    {"source": item.source, "algorithm": item.algorithm, "metadata": item.metadata}
                    for item in database_matches
                ]},
            )
        if last_result:
            last_result.execution_time_ms = elapsed_ms
            return last_result

        return LookupResult(
            status=LookupStatus.NOT_FOUND,
            source="Public Hash Databases",
            details=["No plaintext match found across configured public hash databases."],
            execution_time_ms=elapsed_ms,
        )


# Global registry instance
_LOOKUP_REGISTRY = LookupRegistry()


def execute_lookup(
    hash_value: str, possible_algorithms: Optional[List[str]] = None
) -> LookupResult:
    """Convenience alias for querying the global lookup registry."""
    return _LOOKUP_REGISTRY.execute_lookup(hash_value, possible_algorithms)
