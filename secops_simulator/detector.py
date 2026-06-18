"""Hermetic OWASP-LLM01 prompt-injection / jailbreak detector."""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Pattern


@dataclass(frozen=True)
class Finding:
    family: str
    label: str
    matched: str
    span: tuple[int, int]

    def to_dict(self, show_matches: bool = False) -> dict:
        """Serialise the finding with raw matches masked by default."""
        data = asdict(self)
        if not show_matches:
            data["matched"] = "*" * len(self.matched)
        return data


Signature = tuple[str, str, Pattern[str]]

SIGNATURES: list[Signature] = [
    (
        "instruction-override",
        "ignore prior instructions",
        re.compile(
            r"\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction-override",
        "disregard prior instructions",
        re.compile(
            r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction-override",
        "forget prior context",
        re.compile(
            r"\bforget\s+(?:everything|all)(?:\s+\w+){0,6}\s+"
            r"(?:said|above|instructions)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "persona-jailbreak",
        "DAN persona",
        re.compile(
            r"\b(?:you\s+are\s+DAN|do\s+anything\s+now|DAN\s+mode)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "persona-jailbreak",
        "you are now persona",
        re.compile(
            r"\byou\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|uncensored|"
            r"jailbroken|developer\s+mode|evil|rogue)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "persona-jailbreak",
        "act without restrictions",
        re.compile(
            r"\bact\s+as\s+(?:an?\s+)?[\w -]{1,60}?\s+"
            r"(?:with\s+no|without)\s+(?:restrictions|filter|rules)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "persona-jailbreak",
        "AIM persona",
        re.compile(
            r"\b(?:you\s+are\s+AIM|AIM\s+mode|always\s+intelligent\s+"
            r"and\s+machiavellian)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system-prompt-leak",
        "repeat system prompt",
        re.compile(r"\brepeat\s+your\s+system\s+prompt\b", re.IGNORECASE),
    ),
    (
        "system-prompt-leak",
        "reveal prompt",
        re.compile(
            r"\b(?:reveal|print|show)\s+your\s+(?:system\s+)?"
            r"(?:prompt|instructions)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "system-prompt-leak",
        "ask initial instructions",
        re.compile(
            r"\bwhat\s+(?:are|were)\s+your\s+(?:initial|original)\s+"
            r"instructions\b",
            re.IGNORECASE,
        ),
    ),
    (
        "delimiter-injection",
        "system closing tag",
        re.compile(r"</system>", re.IGNORECASE),
    ),
    (
        "delimiter-injection",
        "chat template marker",
        re.compile(r"<\|im_start\|>", re.IGNORECASE),
    ),
    (
        "delimiter-injection",
        "instruction delimiter",
        re.compile(r"\[INST\]", re.IGNORECASE),
    ),
    (
        "delimiter-injection",
        "markdown system heading",
        re.compile(r"(?m)^\s*#{3,}\s*system\b", re.IGNORECASE),
    ),
    (
        "delimiter-injection",
        "fenced system block",
        re.compile(r"(?m)^\s*```\s*system\b", re.IGNORECASE),
    ),
    (
        "delimiter-injection",
        "begin system block",
        re.compile(r"(?m)^\s*BEGIN\s+SYSTEM\b", re.IGNORECASE),
    ),
    (
        "tool-poisoning",
        "exfiltrate directive",
        re.compile(r"\bexfiltrate\s+(?:credentials|secrets|data|keys?)\b", re.IGNORECASE),
    ),
    (
        "tool-poisoning",
        "pipe curl to shell",
        re.compile(r"\bcurl\b[^\n|]{0,200}\|\s*(?:sh|bash)\b", re.IGNORECASE),
    ),
    (
        "tool-poisoning",
        "recursive delete",
        re.compile(r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\b", re.IGNORECASE),
    ),
    (
        "tool-poisoning",
        "send secrets",
        re.compile(
            r"\bsend\b[^\n.]{0,120}\b(?:credentials|secrets|api\s+key)\b"
            r"[^\n.]{0,120}\bto\b",
            re.IGNORECASE,
        ),
    ),
    (
        "tool-poisoning",
        "base64 decode and run",
        re.compile(
            r"\bbase64\b[^\n.]{0,120}\bdecode\b[^\n.]{0,120}\b"
            r"(?:run|execute|exec)\b",
            re.IGNORECASE,
        ),
    ),
]


def scan(text: str) -> list[Finding]:
    """Scan text and return prompt-injection findings."""
    findings: list[Finding] = []
    for family, label, regex in SIGNATURES:
        for match in regex.finditer(text):
            findings.append(Finding(family, label, match.group(0), match.span()))
    return findings


def _read_target(target: str) -> str:
    path = Path(target)
    if path.exists() and path.is_file():
        return path.read_text(encoding="utf-8")
    return target


def _cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secops_simulator")
    parser.add_argument("target", help="file path or literal text to scan")
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument(
        "--show-matches",
        action="store_true",
        help="reveal raw matched text in the report (default: masked)",
    )
    args = parser.parse_args(argv)

    try:
        text = _read_target(args.target)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = scan(text)
    if args.json:
        json.dump(
            [
                finding.to_dict(show_matches=args.show_matches)
                for finding in findings
            ],
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        print("secops_simulator: OWASP-LLM01 prompt-injection scan")
        print(f"Findings: {len(findings)}")
        for finding in findings:
            shown = finding.to_dict(show_matches=args.show_matches)["matched"]
            start, end = finding.span
            print(
                f"  [{finding.family}] {finding.label} @ "
                f"span=({start},{end}): {shown}"
            )
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
