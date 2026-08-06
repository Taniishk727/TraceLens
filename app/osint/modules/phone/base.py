"""
============================================================
TraceLens Phone Base Collector Interface
============================================================

Defines the Abstract Base Class for all Phone OSINT Collectors.

Author:
    TraceLens
"""

from abc import ABC, abstractmethod
from typing import Any

from app.osint.modules.phone.validator import PhoneValidationResult


class BasePhoneCollector(ABC):
    """
    Abstract Base Class for all Phone OSINT Collectors.
    All collectors inherit from this class and implement collect().
    """

    def __init__(self, name: str, category: str, enabled: bool = True):
        self.name = name
        self.category = category
        self.enabled = enabled

    @abstractmethod
    def collect(self, validation: PhoneValidationResult) -> dict[str, Any]:
        """
        Executes collector logic against the validated phone number data.

        Args:
            validation: PhoneValidationResult dataclass.

        Returns:
            Dictionary containing collector results, findings, and metadata.
        """
        pass
