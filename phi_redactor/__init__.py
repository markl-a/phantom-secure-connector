"""PHI redactor — regex-based de-identification for Taiwan + western identifiers.

Tier 1: regex-only, reversible-mapping by default. LLM-augmented edge-case
catches are planned for Tier 2 via phantom-mesh provider trait.
"""
from .redactor import redact, RedactionMap, PATTERNS

__all__ = ["redact", "RedactionMap", "PATTERNS"]
