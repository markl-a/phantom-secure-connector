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
- TW NHI card     (健保卡)   12 numeric digits
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
    # TW NHI (健保卡) card numbers are 12 NUMERIC digits. The old hex class
    # ``[0-9A-Fa-f]`` produced false positives on ordinary 12-char hex words
    # (e.g. ``deadbeefcafe``), polluting the audit tally with non-PHI. Digits
    # only — no real NHI is missed (NHI is numeric), false positives removed.
    ("TW_NHI",   re.compile(r"\b\d{12}\b")),
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
    # Per-label set of originals already tallied — used by irreversible mask
    # mode to count uniques without storing a reverse mapping.
    _seen: Dict[str, set] = field(default_factory=dict, repr=False)
    # Exact replacement spans in the CLEAN output: (out_start, out_end, original).
    # Span-based restore is byte-exact and immune to the token-collision bug
    # where a naive str.replace would rewrite a literal "[SSN_1]" that happened
    # to already exist in the source text.
    _spans: List[Tuple[int, int, str]] = field(default_factory=list, repr=False)

    def issue(self, label: str, original: str) -> str:
        # Re-use the same token for the same original (idempotent within a doc).
        for token, val in self.items.items():
            if val == original and token.startswith(f"[{label}_"):
                return token
        self.counters[label] = self.counters.get(label, 0) + 1
        token = f"[{label}_{self.counters[label]}]"
        self.items[token] = original
        return token

    def tally(self, label: str, original: str) -> None:
        """Count a redacted item for reporting WITHOUT storing a reverse map.

        Used by irreversible ``mask`` mode so audit metrics (``counters``)
        stay truthful while ``items`` remains empty. Duplicates count once,
        mirroring ``issue``'s idempotency.
        """
        seen = self._seen.setdefault(label, set())
        if original in seen:
            return
        seen.add(original)
        self.counters[label] = self.counters.get(label, 0) + 1

    def record_span(self, out_start: int, out_end: int, original: str) -> None:
        """Record the exact span a token occupies in the CLEAN output so
        ``restore`` can splice the original back byte-exactly."""
        self._spans.append((out_start, out_end, original))

    def restore(self, redacted: str) -> str:
        """Inverse op — reconstruct the original text byte-exactly.

        Uses recorded output spans (not ``str.replace``) so a literal token
        that pre-existed in the source — e.g. the user wrote ``[SSN_1]`` — is
        never mistaken for an issued token and corrupted. Falls back to the
        legacy longest-token replace only when no spans were recorded (e.g. a
        map built by hand in older callers / tests).
        """
        if self._spans:
            out: List[str] = []
            cursor = 0
            for start, end, original in sorted(self._spans):
                out.append(redacted[cursor:start])
                out.append(original)
                cursor = end
            out.append(redacted[cursor:])
            return "".join(out)
        # Legacy fallback: longest tokens first to avoid prefix collisions.
        out_text = redacted
        for token in sorted(self.items, key=len, reverse=True):
            out_text = out_text.replace(token, self.items[token])
        return out_text


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
    # Explicit, early type guard. A non-str input (None/int/dict/bytes handed
    # in by a buggy caller) must fail loudly with a clear contract error rather
    # than a cryptic ``re`` internal crash — and must NEVER pass through
    # un-redacted, which could leak an unscanned object onto the wire.
    if not isinstance(text, str):
        raise TypeError(
            f"redact() expects str, got {type(text).__name__}; "
            "callers must decode/serialise to str before redaction"
        )

    mapping = RedactionMap()
    spans = _walk_matches(text)
    if not spans:
        return text, mapping

    out: List[str] = []
    cursor = 0
    out_len = 0  # running length of the CLEAN output, for span recording
    for s, e, label, original in spans:
        prefix = text[cursor:s]
        out.append(prefix)
        out_len += len(prefix)
        if mode == "replace":
            token = mapping.issue(label, original)
            out.append(token)
            # Record where this token lands in the clean output so restore can
            # splice the original back without a collision-prone str.replace.
            mapping.record_span(out_len, out_len + len(token), original)
            out_len += len(token)
        else:  # mask
            mapping.tally(label, original)  # count even though it's irreversible
            stars = "*" * (e - s)
            out.append(stars)
            out_len += len(stars)
        cursor = e
    out.append(text[cursor:])
    return "".join(out), mapping
