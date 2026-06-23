"""Deterministic, static mapping from capabilities / injection-finding families
to OWASP Top 10 for Agentic Applications 2026 + OWASP LLM + Taiwan PDPA / AI Basic
Act references. Pure lookup — no LLM, no network. Informational only."""
from __future__ import annotations

from typing import Iterable, List

from mcp_bridge.capabilities import Capability

DISCLAIMER = (
    "informational mapping to OWASP / Taiwan PDPA / AI Basic Act — "
    "NOT a certification or legal advice"
)

_CAP_REFS = {
    Capability.NETWORK: [
        "OWASP-AGENTIC-2026: Excessive Agency",
        "TW-PDPA art.27 (security maintenance)",
    ],
    Capability.FILESYSTEM: [
        "OWASP-AGENTIC-2026: Tool Misuse",
    ],
    Capability.SUBPROCESS: [
        "OWASP-AGENTIC-2026: Tool Misuse",
        "TW-PDPA art.27 (security maintenance)",
    ],
    Capability.WRITE: [
        "OWASP-AGENTIC-2026: Tool Misuse",
        "TW-PDPA art.27 (security maintenance)",
    ],
    Capability.PHI_REVERSE: [
        "TW-PDPA art.6 (special category data)",
        "HIPAA minimum-necessary",
    ],
    Capability.PURE: [],
}

_FAMILY_REFS = {
    "instruction-override": [
        "OWASP-LLM01: Prompt Injection",
        "OWASP-AGENTIC-2026: Prompt Injection",
        "TW AI Basic Act (accountability principle)",
    ],
    "delimiter-injection": [
        "OWASP-LLM01: Prompt Injection",
        "OWASP-AGENTIC-2026: Prompt Injection",
    ],
    "persona-jailbreak": [
        "OWASP-LLM01: Prompt Injection",
        "OWASP-AGENTIC-2026: Prompt Injection",
    ],
    "system-prompt-leak": [
        "OWASP-LLM01: Prompt Injection",
        "OWASP-AGENTIC-2026: Sensitive Information Disclosure",
    ],
    "tool-poisoning": [
        "OWASP-AGENTIC-2026: Tool Misuse",
        "OWASP-AGENTIC-2026: Prompt Injection",
    ],
}

_GENERIC_FAMILY_REFS = ["OWASP-LLM01: Prompt Injection"]


def frameworks_for_capabilities(caps: Iterable[Capability]) -> List[str]:
    """Deduped, sorted framework refs for a set of capabilities."""
    out = set()
    for c in caps:
        out.update(_CAP_REFS.get(c, []))
    return sorted(out)


def frameworks_for_finding_family(family: str) -> List[str]:
    """Framework refs for an injection finding family; never empty (generic
    fallback for an unmapped family so audit output is always citable)."""
    return list(_FAMILY_REFS.get(family, _GENERIC_FAMILY_REFS))
