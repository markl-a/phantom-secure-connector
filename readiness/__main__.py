"""CLI: scan a file/dir into a unified data-protection readiness report.

Exit codes (repo contract): 0 clean · 1 findings · 2 operator error."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from readiness.assessor import assess_target
from readiness.report import render_html, to_json

_STANDARDS = ["hipaa", "gdpr", "pci-dss", "tw-pii"]


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(prog="readiness", description="unified data-protection readiness report")
    ap.add_argument("target", help="file or directory to assess")
    ap.add_argument("--standards", default=",".join(_STANDARDS),
                    help="comma list: hipaa,gdpr,pci-dss,tw-pii (default: all)")
    ap.add_argument("--mcp-summary", help="optional secops MCP-scanner summary.json")
    ap.add_argument("--html-out", help="write the HTML report here")
    ap.add_argument("--json", action="store_true", help="emit JSON to stdout")
    ap.add_argument("--show-matches", action="store_true",
                    help="reveal raw matched values (default: masked) — local inspection only")
    args = ap.parse_args(argv)

    if not Path(args.target).exists():
        print(f"error: target not found: {args.target}", file=sys.stderr)
        return 2
    standards = [s.strip() for s in args.standards.split(",") if s.strip()]
    try:
        result = assess_target(args.target, standards, mcp_summary=args.mcp_summary,
                               show_matches=args.show_matches)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.html_out:
        Path(args.html_out).write_text(render_html(result), encoding="utf-8")
        print(f"HTML report written to {args.html_out}")
    if args.json or not args.html_out:
        sys.stdout.write(to_json(result) + "\n")
    return 1 if result["summary"]["verdict"] == "findings" else 0


if __name__ == "__main__":
    raise SystemExit(main())
