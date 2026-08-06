"""
============================================================
TraceLens Email Base Collector Interface
============================================================

Defines the Abstract Base Class for all Email OSINT Collectors.

Author:
    TraceLens
"""

from abc import ABC, abstractmethod
from typing import Any

from app.osint.modules.email.validator import EmailValidationResult


class BaseCollector(ABC):
    """
    Abstract Base Class for all Email OSINT Collectors.
    All collectors inherit from this class and implement collect().
    """

    def __init__(self, name: str, category: str, enabled: bool = True):
        self.name = name
        self.category = category
        self.enabled = enabled

    @abstractmethod
    def collect(self, validation: EmailValidationResult) -> dict[str, Any]:
        """
        Executes collector logic against the validated email data.

        Args:
            validation: EmailValidationResult dataclass.

        Returns:
            Dictionary containing collector results, findings, and metadata.
        """
        pass
