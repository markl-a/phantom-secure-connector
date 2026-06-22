"""Compose phi_redactor + compliance_checker + secops_simulator into one
deterministic, local, no-LLM data-protection readiness result. PHI masked by
default; this module never connects to anything (pure file read)."""

from __future__ import annotations

from pathlib import Path

from phi_redactor.redactor import redact
from secops_simulator import scan

from compliance_checker.checker import load_standard, scan_file

_STRUCTURED = {".csv", ".json"}


def phi_coverage(text: str) -> dict:
    """Per-label PHI counts found in `text` (no raw values), via mask mode."""
    _clean, mapping = redact(text, mode="mask")
    return dict(mapping.counters)


def injection_findings(text: str, show_matches: bool = False) -> list:
    """Prompt-injection/jailbreak findings (masked by default)."""
    return [f.to_dict(show_matches=show_matches) for f in scan(text)]


def compliance_findings(path: str, standards: list, show_matches: bool = False) -> dict:
    """For each standard, masked violations from a CSV/JSON file. Non-structured
    files (.txt/.md) yield {} (compliance scanning is row/field based). Raises
    FileNotFoundError for an unknown standard (propagated from load_standard)."""
    p = Path(path)
    if p.suffix.lower() not in _STRUCTURED:
        return {}
    out: dict = {}
    for std in standards:
        rs = load_standard(std)  # FileNotFoundError on unknown standard
        vios = scan_file(p, rs)
        out[std] = [v.to_dict(show_matches=show_matches) for v in vios]
    return out
