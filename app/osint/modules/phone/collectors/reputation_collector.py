"""
============================================================
TraceLens Phone Reputation Collector Module Re-export
============================================================

Maintains backward-compatibility by re-exporting ReputationCollector
from the dedicated reputation subpackage.
"""

from app.osint.modules.phone.collectors.reputation.collector import ReputationCollector

__all__ = ["ReputationCollector"]
