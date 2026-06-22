"""Compose phi_redactor + compliance_checker + secops_simulator into one
deterministic, local, no-LLM data-protection readiness result. PHI masked by
default; this module never connects to anything (pure file read)."""

from __future__ import annotations

from phi_redactor.redactor import redact
from secops_simulator import scan


def phi_coverage(text: str) -> dict:
    """Per-label PHI counts found in `text` (no raw values), via mask mode."""
    _clean, mapping = redact(text, mode="mask")
    return dict(mapping.counters)


def injection_findings(text: str, show_matches: bool = False) -> list:
    """Prompt-injection/jailbreak findings (masked by default)."""
    return [f.to_dict(show_matches=show_matches) for f in scan(text)]
