"""Compliance checker — scan CSV/JSON for HIPAA / GDPR / 個資法 violations.

Tier 1: rules loaded from TOML files in ``rules/``. Each rule = (id, label,
regex). The checker walks every cell and yields ``Violation`` records.
"""
from .checker import Violation, scan_file, scan_records, load_rules

__all__ = ["Violation", "scan_file", "scan_records", "load_rules"]
