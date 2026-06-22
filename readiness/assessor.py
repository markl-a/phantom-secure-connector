"""Compose phi_redactor + compliance_checker + secops_simulator into one
deterministic, local, no-LLM data-protection readiness result. PHI masked by
default; this module never connects to anything (pure file read)."""

from __future__ import annotations

import json
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


def load_mcp_summary(path: str) -> list:
    """Parse a secops MCP-scanner summary.json into a flat risk list."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for f in data.get("findings", []):
        out.append({
            "severity": f.get("severity"),
            "severity_name": f.get("severity_name"),
            "rule_id": f.get("rule_id"),
            "server": f.get("server"),
            "tool": f.get("tool"),
            "owasp": f.get("owasp"),
            "message": f.get("message"),
        })
    return out


def assess(target: str, standards: list, mcp_summary: str | None = None,
           show_matches: bool = False) -> dict:
    """Run all engines over one file and return the unified result dict. Pure
    file read; no network, no LLM."""
    text = Path(target).read_text(encoding="utf-8", errors="replace")
    compliance = compliance_findings(target, standards, show_matches=show_matches)
    phi = phi_coverage(text)
    injection = injection_findings(text, show_matches=show_matches)
    mcp = load_mcp_summary(mcp_summary) if mcp_summary else []
    compliance_total = sum(len(v) for v in compliance.values())
    phi_total = sum(phi.values())
    injection_total = len(injection)
    mcp_total = len(mcp)
    total = compliance_total + phi_total + injection_total + mcp_total
    return {
        "target": target,
        "standards": list(standards),
        "compliance": compliance,
        "phi_coverage": phi,
        "injection": injection,
        "mcp": mcp,
        "summary": {
            "compliance_total": compliance_total,
            "phi_total": phi_total,
            "injection_total": injection_total,
            "mcp_total": mcp_total,
            "verdict": "findings" if total else "clean",
        },
    }


SUPPORTED_EXTS = {".csv", ".json", ".txt", ".md"}


def merge_results(results: list, target: str, standards: list) -> dict:
    """Merge per-file results into one. PHI counts sum per label; compliance,
    injection, mcp lists concatenate; verdict recomputed."""
    phi: dict = {}
    compliance: dict = {}
    injection: list = []
    mcp: list = []
    for r in results:
        for k, n in r["phi_coverage"].items():
            phi[k] = phi.get(k, 0) + n
        for std, vios in r["compliance"].items():
            compliance.setdefault(std, []).extend(vios)
        injection.extend(r["injection"])
        mcp.extend(r["mcp"])
    compliance_total = sum(len(v) for v in compliance.values())
    phi_total = sum(phi.values())
    total = compliance_total + phi_total + len(injection) + len(mcp)
    return {
        "target": target, "standards": list(standards),
        "compliance": compliance, "phi_coverage": phi,
        "injection": injection, "mcp": mcp,
        "summary": {
            "compliance_total": compliance_total, "phi_total": phi_total,
            "injection_total": len(injection), "mcp_total": len(mcp),
            "verdict": "findings" if total else "clean",
        },
    }


def assess_target(target: str, standards: list, mcp_summary: str | None = None,
                  show_matches: bool = False) -> dict:
    """Assess a single file or a directory (recursed for SUPPORTED_EXTS)."""
    p = Path(target)
    if p.is_dir():
        files = sorted(f for f in p.rglob("*")
                       if f.is_file() and f.suffix.lower() in SUPPORTED_EXTS)
        results = []
        for f in files:
            try:
                results.append(assess(str(f), standards, show_matches=show_matches))
            except (UnicodeDecodeError, ValueError, OSError):
                # Skip a file we can't read/parse (e.g. malformed JSON) rather
                # than aborting the whole directory assessment.
                continue
        merged = merge_results(results, target, standards)
        if mcp_summary:
            merged["mcp"] = load_mcp_summary(mcp_summary)
            merged["summary"]["mcp_total"] = len(merged["mcp"])
            if merged["mcp"]:
                merged["summary"]["verdict"] = "findings"
        return merged
    return assess(target, standards, mcp_summary=mcp_summary, show_matches=show_matches)
