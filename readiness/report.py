"""Render a unified data-protection readiness result as JSON or a self-contained,
XSS-safe HTML report (style mirrors compliance_checker.render_html)."""

from __future__ import annotations

import html
import json

_STYLE = (
    "body{font-family:Arial,sans-serif;margin:2rem;color:#222}"
    "h1{margin-top:0}h2{margin-top:1.5rem}"
    "table{border-collapse:collapse;width:100%;margin:.5rem 0}"
    "th,td{border:1px solid #ccc;padding:.5rem;text-align:left;vertical-align:top}"
    "th{background:#f3f3f3}.disclaimer{margin-top:2rem;color:#555;font-size:.9rem}"
)


def to_json(result: dict) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2)


def _table(headers: list, rows: list) -> list:
    parts = ["<table><thead><tr>"]
    parts += [f"<th>{html.escape(h)}</th>" for h in headers]
    parts.append("</tr></thead><tbody>")
    for row in rows:
        parts.append("<tr>" + "".join(f"<td>{html.escape(str(c))}</td>" for c in row) + "</tr>")
    parts.append("</tbody></table>")
    return parts


def render_html(result: dict) -> str:
    s = result["summary"]
    p = [
        "<!DOCTYPE html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
        "<title>Data-Protection Readiness Report</title>", f"<style>{_STYLE}</style>",
        "</head>", "<body>", "<h1>Data-Protection Readiness Report</h1>",
        f"<p><b>Target:</b> {html.escape(str(result['target']))}<br>"
        f"<b>Standards:</b> {html.escape(', '.join(result['standards']))}<br>"
        f"<b>Verdict:</b> {html.escape(s['verdict'])} "
        f"(PHI {s['phi_total']}, compliance {s['compliance_total']}, "
        f"injection {s['injection_total']}, MCP {s['mcp_total']})</p>",
    ]
    any_section = False
    if result["phi_coverage"]:
        any_section = True
        p.append("<h2>PHI coverage (types &amp; counts)</h2>")
        p += _table(["PHI type", "count"], sorted(result["phi_coverage"].items()))
    for std, vios in result["compliance"].items():
        if vios:
            any_section = True
            p.append(f"<h2>Compliance — {html.escape(std)} (OWASP/HIPAA/GDPR/PCI/TW-PII)</h2>")
            p += _table(["rule", "location", "match"],
                        [(v["rule_id"], v["location"], v["matched"]) for v in vios])
    if result["injection"]:
        any_section = True
        p.append("<h2>Prompt-injection (OWASP LLM01)</h2>")
        p += _table(["family", "label", "match"],
                    [(f["family"], f["label"], f["matched"]) for f in result["injection"]])
    if result["mcp"]:
        any_section = True
        p.append("<h2>MCP config risks (OWASP MCP)</h2>")
        p += _table(["severity", "rule", "scope", "message"],
                    [(m["severity_name"], m["rule_id"],
                      f"{m['server']}/{m['tool']}", m["message"]) for m in result["mcp"]])
    if not any_section:
        p.append("<p>No findings — the scanned target is clean for the selected checks.</p>")
    p.append(
        '<p class="disclaimer">This is an automated <b>scan-assist</b> report, '
        "<b>not</b> a legal or compliance certification; PHI is masked by default. "
        "De-identification is not anonymization — review with a qualified professional.</p>"
    )
    p += ["</body>", "</html>"]
    return "\n".join(p)
