"""Compliance scanner: load rule files, scan CSV/JSON, emit violations.

Designed stdlib-only. TOML rule files are parsed with a tiny purpose-built
reader (only the subset we use: top-level scalars and ``[[rule]]`` arrays of
tables with string fields). This keeps the connector dependency-free on
Python 3.10+.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Iterable, List, Pattern, Tuple

RULES_DIR = Path(__file__).resolve().parent / "rules"


@dataclass
class Rule:
    id: str
    label: str
    regex: Pattern[str]


@dataclass
class RuleSet:
    standard: str
    version: str
    rules: List[Rule]


@dataclass
class Violation:
    rule_id: str
    rule_label: str
    standard: str
    location: str           # e.g. "row=3 col=name" or "json:patients[0].dob"
    matched: str

    def to_dict(self) -> Dict[str, str]:
        d = asdict(self)
        return d


# ----------------------------- tiny TOML parser -----------------------------
def _parse_toml(text: str) -> Dict:
    """Parse the subset of TOML used in our rule files.

    Supported:
    - top-level ``key = "value"`` scalars (strings only)
    - ``[[rule]]`` arrays of tables, each containing only string fields

    Anything else raises ValueError. This is deliberately tiny so we keep
    the connector stdlib-only on Python 3.10.
    """
    out: Dict = {}
    current_array: List[Dict] = []
    current_table: Dict = None  # type: ignore[assignment]
    array_key: str = ""

    def _unquote(s: str) -> str:
        s = s.strip()
        if (s.startswith('"') and s.endswith('"')) or (
            s.startswith("'") and s.endswith("'")
        ):
            body = s[1:-1]
            # Minimal escape handling for the chars we actually use.
            return (
                body.replace("\\\\", "\\")
                .replace('\\"', '"')
                .replace("\\n", "\n")
                .replace("\\t", "\t")
            )
        raise ValueError(f"expected quoted string, got {s!r}")

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[[") and line.endswith("]]"):
            key = line[2:-2].strip()
            if current_table is not None:
                current_array.append(current_table)
            if array_key and array_key != key:
                out[array_key] = current_array
                current_array = []
            array_key = key
            current_table = {}
            continue
        if "=" not in line:
            raise ValueError(f"unparseable TOML line: {raw!r}")
        k, _, v = line.partition("=")
        k = k.strip()
        v = v.strip()
        # Strip trailing comments (only if not inside a quoted string — our
        # rule files keep comments on their own lines, so this is safe).
        if (
            "#" in v
            and not (v.startswith('"') and v.rstrip().endswith('"'))
        ):
            # Best-effort: cut at the first " #" sequence after the closing
            # quote, if any.
            hash_pos = v.find(" #")
            if hash_pos != -1:
                v = v[:hash_pos].strip()
        value = _unquote(v)
        if current_table is None:
            out[k] = value
        else:
            current_table[k] = value

    if current_table is not None:
        current_array.append(current_table)
    if array_key:
        out[array_key] = current_array
    return out


# ----------------------------- public API -----------------------------------
def load_rules(path: Path) -> RuleSet:
    """Load a TOML rule file from ``path``."""
    raw = _parse_toml(Path(path).read_text(encoding="utf-8"))
    standard = raw.get("standard", "UNKNOWN")
    version = raw.get("version", "0")
    rules_raw = raw.get("rule", [])
    rules = [
        Rule(
            id=r["id"],
            label=r["label"],
            regex=re.compile(r["regex"]),
        )
        for r in rules_raw
    ]
    return RuleSet(standard=standard, version=version, rules=rules)


def load_standard(name: str) -> RuleSet:
    """Load a known standard by name (case-insensitive): hipaa | gdpr."""
    fname = f"{name.lower()}.toml"
    p = RULES_DIR / fname
    if not p.exists():
        raise FileNotFoundError(
            f"unknown standard {name!r}; tried {p}"
        )
    return load_rules(p)


def scan_records(
    records: Iterable[Dict[str, str]],
    ruleset: RuleSet,
    location_prefix: str = "row",
) -> List[Violation]:
    """Scan an iterable of dict records (e.g. csv.DictReader output)."""
    out: List[Violation] = []
    for i, rec in enumerate(records):
        for col, val in rec.items():
            if val is None:
                continue
            sval = str(val)
            for rule in ruleset.rules:
                for m in rule.regex.finditer(sval):
                    out.append(
                        Violation(
                            rule_id=rule.id,
                            rule_label=rule.label,
                            standard=ruleset.standard,
                            location=f"{location_prefix}={i} col={col}",
                            matched=m.group(0),
                        )
                    )
    return out


def _walk_json(obj, path: str = "$"):
    """Yield (path, str_value) pairs for every leaf in a JSON tree."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_json(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_json(v, f"{path}[{i}]")
    elif obj is not None:
        yield path, str(obj)


def scan_file(path: Path, ruleset: RuleSet) -> List[Violation]:
    """Scan a CSV or JSON file."""
    p = Path(path)
    if p.suffix.lower() == ".csv":
        with p.open(newline="", encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            return scan_records(reader, ruleset, location_prefix="row")
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        violations: List[Violation] = []
        for loc, sval in _walk_json(data):
            for rule in ruleset.rules:
                for m in rule.regex.finditer(sval):
                    violations.append(
                        Violation(
                            rule_id=rule.id,
                            rule_label=rule.label,
                            standard=ruleset.standard,
                            location=loc,
                            matched=m.group(0),
                        )
                    )
        return violations
    raise ValueError(f"unsupported file type: {p.suffix}")


def _cli(argv: List[str] = None) -> int:
    ap = argparse.ArgumentParser(prog="compliance_checker")
    ap.add_argument("--standard", required=True, help="hipaa | gdpr")
    ap.add_argument("path", help="CSV or JSON file to scan")
    ap.add_argument("--json", action="store_true", help="emit JSON output")
    args = ap.parse_args(argv)

    rs = load_standard(args.standard)
    vio = scan_file(Path(args.path), rs)

    if args.json:
        json.dump([v.to_dict() for v in vio], sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"Standard: {rs.standard} v{rs.version}")
        print(f"Violations: {len(vio)}")
        for v in vio:
            print(f"  [{v.rule_id}] {v.rule_label} @ {v.location}: {v.matched!r}")
    return 0 if not vio else 1


if __name__ == "__main__":
    raise SystemExit(_cli())
