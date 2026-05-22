"""Regex-first PHI detector + redactor.

Design:
- Each PHI type has a labelled regex.
- ``redact(text, mode)`` walks every match, replaces with a token, and returns
  a reversible mapping (``mode="replace"``) or an irreversible mask
  (``mode="mask"``).
- Order matters: longer / more specific patterns run first so e.g. an SSN is
  not partially captured by the generic phone pattern.

Coverage (Tier 1):
- TW national ID  (身分證)   ``[A-Z][12][0-9]{8}``
- TW NHI card     (健保卡)   12-hex digits
- TW phone         09xx-xxx-xxx and 02-xxxx-xxxx style
- US SSN          ``\\d{3}-\\d{2}-\\d{4}``
- Email
- Medical record  ``MRN-[A-Z0-9]+`` (Taiwan hospital common form)
- Dates of birth  ``YYYY[-/]MM[-/]DD`` and ``YYYY 年 MM 月 DD 日``
- IPv4
- Credit card     16-digit groups (Luhn-loose; tightened in Tier 2)

NOT YET COVERED (Tier 2 work, documented):
- Personal names — needs NER, not regex.
- Free-text addresses — needs NER + LLM judgement.
- Sub-categories of HIPAA 18 (biometrics, vehicle IDs, etc.) — added on
  request, no demand in early users.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Pattern, Tuple

# Each tuple: (label, compiled_regex). Ordering = priority.
PATTERNS: List[Tuple[str, Pattern[str]]] = [
    ("TW_NHI",   re.compile(r"\b[0-9A-Fa-f]{12}\b")),
    ("SSN",      re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT",   re.compile(r"\b(?:\d[ -]?){15,18}\d\b")),
    ("MRN",      re.compile(r"\bMRN[-_]?[A-Z0-9]{4,12}\b", re.IGNORECASE)),
    ("TW_ID",    re.compile(r"\b[A-Z][12]\d{8}\b")),
    ("EMAIL",    re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")),
    ("DOB_ISO",  re.compile(r"\b(?:19|20)\d{2}[-/](?:0?[1-9]|1[0-2])[-/](?:0?[1-9]|[12]\d|3[01])\b")),
    ("DOB_ZH",   re.compile(r"(?:19|20)\d{2}\s*年\s*(?:0?[1-9]|1[0-2])\s*月\s*(?:0?[1-9]|[12]\d|3[01])\s*日")),
    ("TW_PHONE_M", re.compile(r"\b09\d{2}[- ]?\d{3}[- ]?\d{3}\b")),
    ("TW_PHONE_L", re.compile(r"\b0[2-8][- ]?\d{3,4}[- ]?\d{4}\b")),
    ("IPV4",     re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")),
]


@dataclass
class RedactionMap:
    """Reversible mapping: token -> original string + per-label counters."""

    items: Dict[str, str] = field(default_factory=dict)
    counters: Dict[str, int] = field(default_factory=dict)

    def issue(self, label: str, original: str) -> str:
        # Re-use the same token for the same original (idempotent within a doc).
        for token, val in self.items.items():
            if val == original and token.startswith(f"[{label}_"):
                return token
        self.counters[label] = self.counters.get(label, 0) + 1
        token = f"[{label}_{self.counters[label]}]"
        self.items[token] = original
        return token

    def restore(self, redacted: str) -> str:
        """Inverse op — useful for round-trip tests."""
        out = redacted
        # Replace longest tokens first to avoid prefix collisions.
        for token in sorted(self.items, key=len, reverse=True):
            out = out.replace(token, self.items[token])
        return out


def _walk_matches(text: str) -> List[Tuple[int, int, str, str]]:
    """Return list of (start, end, label, matched_text) with overlaps removed
    by priority (earlier-in-PATTERNS wins)."""
    spans: List[Tuple[int, int, str, str]] = []
    claimed: List[Tuple[int, int]] = []
    for label, rx in PATTERNS:
        for m in rx.finditer(text):
            s, e = m.span()
            # Skip if any char in this span is already claimed.
            if any(not (e <= cs or s >= ce) for cs, ce in claimed):
                continue
            spans.append((s, e, label, m.group(0)))
            claimed.append((s, e))
    spans.sort(key=lambda t: t[0])
    return spans


def redact(text: str, mode: str = "replace") -> Tuple[str, RedactionMap]:
    """Redact PHI in ``text``.

    Parameters
    ----------
    text : str
        Free-text input that may contain PHI.
    mode : {"replace", "mask"}
        - "replace" → tokenise e.g. ``[SSN_1]`` and return reversible map.
        - "mask"    → overwrite with ``*`` of equal length; map is empty.

    Returns
    -------
    (clean_text, RedactionMap)
    """
    if mode not in ("replace", "mask"):
        raise ValueError(f"mode must be 'replace' or 'mask', got {mode!r}")

    mapping = RedactionMap()
    spans = _walk_matches(text)
    if not spans:
        return text, mapping

    out: List[str] = []
    cursor = 0
    for s, e, label, original in spans:
        out.append(text[cursor:s])
        if mode == "replace":
            out.append(mapping.issue(label, original))
        else:  # mask
            out.append("*" * (e - s))
        cursor = e
    out.append(text[cursor:])
    return "".join(out), mapping
