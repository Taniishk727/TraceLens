"""
============================================================
TraceLens Phone Risk Collector Module Re-export
============================================================

Maintains backward-compatibility by re-exporting RiskCollector
from the dedicated risk subpackage.
"""

from app.osint.modules.phone.collectors.risk.collector import RiskCollector

__all__ = ["RiskCollector"]
