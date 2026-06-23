"""MCP-style server exposing the phantom security suite over JSON-RPC.

Tier 1 skeleton: we model the MCP request/response surface (tools/list,
tools/call) over plain JSON-RPC so the wiring can be verified without a hard
dependency on ``mcp``/``fastmcp``. Swap transport for the official SDK once
Anthropic's spec stabilises.

Tools exposed:
- ``redact_phi``            — de-identify PHI/PII (this suite's own capability)
- ``list_standards``        — list compliance standards from compliance_checker/rules/*.toml
- ``compliance_scan``       — scan free text for compliance violations
- ``compliance_scan_file``  — scan CSV/JSON files for compliance violations
- ``mask_text``             — reversibly tokenise PHI/PII, returning tokens + handle
- ``restore_text``          — restore text from a mask_text handle + tokenised text
- ``phantom_status``        — GET http://127.0.0.1:7878/api/status
- ``phantom_fts5_search``   — search via ``phantom recall`` (decrypts events/; sqlite index is dead)
- ``phantom_event_capture`` — subprocess ``phantom event capture --text <text>``

Driven over stdio for Claude Desktop, or imported as a library for unit tests.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Make the sibling phi_redactor importable when run as `python mcp_bridge/server.py`.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phi_redactor.redactor import redact, RedactionMap  # noqa: E402
from compliance_checker.checker import load_standard, scan_records, scan_file, RULES_DIR  # noqa: E402
from mcp_bridge.capabilities import Capability, CapabilityPolicy  # noqa: E402
from mcp_bridge.frameworks import frameworks_for_capabilities  # noqa: E402

PHANTOM_STATUS_URL = "http://127.0.0.1:7878/api/status"

# In-process store of reversible redaction maps, keyed by an opaque handle.
# mask_text returns ONLY tokens to the caller (no raw PHI crosses the wire);
# the reverse map stays server-side and is consumed by restore_text. A simple
# monotonic counter keeps handles unique within a server process (no Date/rand).
_REDACTION_STORE: Dict[str, RedactionMap] = {}
_REDACTION_SEQ: List[int] = [0]


def _safe(value: Any) -> str:
    """Mask PHI in any diagnostic string before it leaves the process.

    Subprocess error text (``str(TimeoutExpired)`` includes the full command
    line, which embeds the caller's ``query``/``text`` — potential PHI) and a
    child's ``stderr`` can echo PHI. Every such string crosses the wire to the
    MCP client, so the error/diagnostic surface must be masked exactly like the
    primary payload. Mask mode is irreversible — appropriate for a one-way log
    line."""
    masked, _ = redact(str(value), mode="mask")
    return masked


@dataclass
class Tool:
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[[Dict[str, Any]], Dict[str, Any]]
    capabilities: frozenset = field(default_factory=frozenset)


# ----------------------------- tool handlers --------------------------------
def phantom_status(_args: Dict[str, Any]) -> Dict[str, Any]:
    """Fetch /api/status from the local phantom coordinator."""
    try:
        with urllib.request.urlopen(PHANTOM_STATUS_URL, timeout=2) as resp:
            body = resp.read().decode("utf-8")
            return {"ok": True, "status": json.loads(body)}
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return {"ok": False, "error": str(exc), "url": PHANTOM_STATUS_URL}


def phantom_fts5_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """Search phantom's event timeline via `phantom recall --json` (decrypts events/).

    NOTE: events.sqlite/fts5_events is dead scaffolding (contentless, never synced);
    `phantom recall` is the supported read interface. Empty query → recent listing.
    Each result: {event_id, timestamp, kind, summary}.
    """
    query = args.get("query", "")
    limit = int(args.get("limit", 10))
    if not shutil.which("phantom"):
        return {"ok": True, "query": query, "results": [], "note": "phantom not on PATH"}
    try:
        proc = subprocess.run(
            ["phantom", "recall", query, "--json", "--limit", str(limit)],
            capture_output=True, encoding="utf-8", errors="replace", timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        # str(TimeoutExpired) embeds the full command line (incl. the query,
        # which may be PHI); child stderr can echo PHI too. Mask both.
        return {"ok": False, "error": _safe(exc)}
    if proc.returncode != 0:
        return {"ok": False, "error": _safe(proc.stderr.strip()[:200]) or "phantom recall failed"}
    try:
        results = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"bad recall json: {_safe(exc)}"}
    return {"ok": True, "query": query, "results": results}


def redact_phi(args: Dict[str, Any]) -> Dict[str, Any]:
    """De-identify PHI/PII in text via phi_redactor — the suite's own capability."""
    text = args.get("text", "")
    mode = args.get("mode", "replace")
    if not text:
        return {"ok": False, "error": "missing 'text' argument"}
    if mode not in ("replace", "mask"):
        # A bad mode from a remote tools/call must not raise (which would crash
        # the serve loop) — return a clean, readable error instead. Do NOT echo
        # the raw mode value: a buggy/hostile caller could smuggle PHI into the
        # mode field, and the error message crosses the wire.
        return {"ok": False, "error": "mode must be 'replace' or 'mask'"}
    clean, mapping = redact(text, mode=mode)
    # Count from `counters`, not `len(items)`: mask mode is irreversible and
    # leaves `items` empty, but the audit metrics must still be truthful.
    count = sum(mapping.counters.values())
    return {"ok": True, "redacted": clean, "count": count, "by_type": mapping.counters}


def list_standards(_args: Dict[str, Any]) -> Dict[str, Any]:
    """List the real compliance standards available (compliance_checker/rules/*.toml)."""
    names = sorted(p.stem for p in RULES_DIR.glob("*.toml"))
    return {"ok": True, "standards": names}


def compliance_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Scan free text for compliance violations via the REAL compliance_checker
    engine (scan_records). Matched values are MASKED by default (Violation.to_dict)."""
    text = args.get("text", "")
    standard = args.get("standard", "")
    if not text:
        return {"ok": False, "error": "missing 'text' argument"}
    if not standard:
        return {"ok": False, "error": "missing 'standard' argument"}
    try:
        rs = load_standard(standard)
    except (FileNotFoundError, ValueError) as exc:
        return {"ok": False, "error": _safe(exc)}
    violations = scan_records([{"text": text}], rs)
    return {
        "ok": True,
        "standard": rs.standard,
        "count": len(violations),
        "violations": [v.to_dict() for v in violations],
    }


def compliance_scan_file(args: Dict[str, Any]) -> Dict[str, Any]:
    """Scan a CSV/JSON FILE for compliance violations via the REAL scan_file engine.
    Matched values are MASKED by default."""
    path = args.get("path", "")
    standard = args.get("standard", "")
    if not path:
        return {"ok": False, "error": "missing 'path' argument"}
    if not standard:
        return {"ok": False, "error": "missing 'standard' argument"}
    try:
        rs = load_standard(standard)
    except (FileNotFoundError, ValueError) as exc:
        return {"ok": False, "error": _safe(exc)}
    try:
        violations = scan_file(Path(path), rs)
    except FileNotFoundError:
        return {"ok": False, "error": "input file not found"}
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": _safe(exc)}
    return {
        "ok": True,
        "standard": rs.standard,
        "count": len(violations),
        "violations": [v.to_dict() for v in violations],
    }


def mask_text(args: Dict[str, Any]) -> Dict[str, Any]:
    """Tokenise PHI reversibly via the REAL phi_redactor (redact mode='replace').
    Returns ONLY the tokenised text + a handle; the reverse map stays server-side
    so no raw PHI crosses the wire. Pair with restore_text for a byte-exact round-trip."""
    text = args.get("text", "")
    if not text:
        return {"ok": False, "error": "missing 'text' argument"}
    clean, mapping = redact(text, mode="replace")
    _REDACTION_SEQ[0] += 1
    handle = f"red-{_REDACTION_SEQ[0]}"
    _REDACTION_STORE[handle] = mapping
    count = sum(mapping.counters.values())
    return {"ok": True, "handle": handle, "redacted": clean, "count": count, "by_type": mapping.counters}


def restore_text(args: Dict[str, Any]) -> Dict[str, Any]:
    """Inverse of mask_text: reconstruct the ORIGINAL text byte-exactly via the
    REAL RedactionMap.restore, using the server-side map referenced by handle.
    redacted must be the unmodified output of the paired mask_text call. This tool
    deliberately returns the original (its sole purpose is de-tokenising for the
    same caller who created the handle)."""
    handle = args.get("handle", "")
    redacted = args.get("redacted", "")
    mapping = _REDACTION_STORE.get(handle)
    if mapping is None:
        return {"ok": False, "error": "unknown or expired handle"}
    restored = mapping.restore(redacted)
    return {"ok": True, "restored": restored}


def phantom_event_capture(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run ``phantom event capture --text <text>`` if the phantom binary is in PATH."""
    text = args.get("text", "")
    if not text:
        return {"ok": False, "error": "missing 'text' argument"}
    phantom_bin = shutil.which("phantom")
    if not phantom_bin:
        return {"ok": False, "error": "phantom binary not in PATH"}
    try:
        proc = subprocess.run(
            [phantom_bin, "event", "capture", "--text", text],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        # stderr is a pure diagnostic surface — phantom may echo the captured
        # "--text <PHI>" there on error; mask it before it crosses the wire.
        # stdout is the tool's legitimate result returned to the same caller
        # who supplied the text, so it is left intact.
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": _safe(proc.stderr),
        }
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        # str(TimeoutExpired) includes the full argv — here "--text <PHI>".
        # Mask before it crosses the wire.
        return {"ok": False, "error": _safe(exc)}


# ----------------------------- server core ----------------------------------
DEFAULT_TOOLS: List[Tool] = [
    Tool(
        name="phantom_status",
        description="Get the local phantom coordinator status snapshot.",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=phantom_status,
        capabilities=frozenset({Capability.NETWORK}),
    ),
    Tool(
        name="phantom_fts5_search",
        description="Search phantom's event timeline via phantom recall (decrypts events/).",
        input_schema={
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
        handler=phantom_fts5_search,
        capabilities=frozenset({Capability.SUBPROCESS}),
    ),
    Tool(
        name="phantom_event_capture",
        description="Capture a free-text event into the phantom timeline.",
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        handler=phantom_event_capture,
        capabilities=frozenset({Capability.SUBPROCESS, Capability.WRITE}),
    ),
    Tool(
        name="redact_phi",
        description="De-identify PHI/PII in text (the security suite's own tool).",
        input_schema={
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "mode": {"type": "string", "enum": ["replace", "mask"]},
            },
            "required": ["text"],
        },
        handler=redact_phi,
        capabilities=frozenset({Capability.PURE}),
    ),
    Tool(
        name="list_standards",
        description="List the available compliance standards (hipaa/gdpr/pci-dss/tw-pii).",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=list_standards,
        capabilities=frozenset({Capability.PURE}),
    ),
    Tool(
        name="compliance_scan",
        description="Scan free text for compliance violations (matched values masked).",
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}, "standard": {"type": "string"}},
            "required": ["text", "standard"],
        },
        handler=compliance_scan,
        capabilities=frozenset({Capability.PURE}),
    ),
    Tool(
        name="compliance_scan_file",
        description="Scan a CSV/JSON file for compliance violations (matched values masked).",
        input_schema={
            "type": "object",
            "properties": {"path": {"type": "string"}, "standard": {"type": "string"}},
            "required": ["path", "standard"],
        },
        handler=compliance_scan_file,
        capabilities=frozenset({Capability.FILESYSTEM}),
    ),
    Tool(
        name="mask_text",
        description="Reversibly tokenise PHI; returns tokens + a handle (round-trip with restore_text).",
        input_schema={
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
        handler=mask_text,
        capabilities=frozenset({Capability.PURE}),
    ),
    Tool(
        name="restore_text",
        description="Reconstruct original text byte-exactly from a mask_text handle + redacted text.",
        input_schema={
            "type": "object",
            "properties": {"handle": {"type": "string"}, "redacted": {"type": "string"}},
            "required": ["handle", "redacted"],
        },
        handler=restore_text,
        capabilities=frozenset({Capability.PHI_REVERSE}),
    ),
]


@dataclass
class PhantomMCPServer:
    tools: List[Tool] = field(default_factory=lambda: list(DEFAULT_TOOLS))
    policy: CapabilityPolicy = field(default_factory=CapabilityPolicy)

    def tool_names(self) -> List[str]:
        return [t.name for t in self.tools]

    def find(self, name: str) -> Optional[Tool]:
        for t in self.tools:
            if t.name == name:
                return t
        return None

    # ---- JSON-RPC subset ----
    def handle(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a single JSON-RPC-style request."""
        rid = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {}) or {}

        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": rid,
                "result": {
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.input_schema,
                            "capabilities": sorted(c.value for c in t.capabilities),
                            "frameworks": frameworks_for_capabilities(t.capabilities),
                        }
                        for t in self.tools
                    ]
                },
            }
        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments", {}) or {}
            tool = self.find(name)
            if tool is None:
                # Do NOT echo the caller-controlled tool name (even masked):
                # a static message can never leak PHI. The valid tool set is
                # discoverable via tools/list.
                return {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": -32601, "message": "unknown tool requested"},
                }
            # Capability gate (least privilege): a tool whose required
            # capabilities are not ALL granted by the active policy is DENIED —
            # the handler never runs. The error message is static (only the
            # tool's own declared capability names, never caller-controlled
            # input), so it cannot leak PHI. -32040 = capability denied.
            missing = self.policy.missing(tool.capabilities)
            if missing:
                denied = ", ".join(sorted(c.value for c in missing))
                return {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {
                        "code": -32040,
                        "message": f"capability denied: tool requires un-granted [{denied}]",
                    },
                }
            # Guard the handler: a single bad call (bad args, an unexpected
            # handler bug) must become a JSON-RPC error, never an exception that
            # escapes serve_stdio and tears down the server for every later
            # caller. -32603 = JSON-RPC "Internal error".
            #
            # PHI safety: the exception message may echo the handler's input,
            # and input may contain PHI. The error crosses the wire to the
            # client, so the message MUST be redacted before it leaves. We keep
            # the exception type (debuggable) and run the detail through our own
            # masker so no raw PHI escapes via the error channel.
            try:
                result = tool.handler(args)
            except Exception as exc:  # noqa: BLE001 — fail-soft at the bridge edge
                safe_detail = _safe(exc)
                return {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {
                        "code": -32603,
                        "message": f"{type(exc).__name__}: {safe_detail}",
                    },
                }
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "error": {"code": -32601, "message": "unknown method requested"},
        }

    def serve_stdio(self) -> None:
        """Read newline-delimited JSON requests from stdin, write responses to
        stdout. Suitable for Claude Desktop's stdio MCP transport."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError as exc:
                resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"parse error: {exc}"},
                }
            else:
                resp = self.handle(req)
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    PhantomMCPServer().serve_stdio()
