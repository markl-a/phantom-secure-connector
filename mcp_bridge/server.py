"""MCP-style server exposing the phantom security suite over JSON-RPC.

Tier 1 skeleton: we model the MCP request/response surface (tools/list,
tools/call) over plain JSON-RPC so the wiring can be verified without a hard
dependency on ``mcp``/``fastmcp``. Swap transport for the official SDK once
Anthropic's spec stabilises.

Tools exposed:
- ``redact_phi``            — de-identify PHI/PII (this suite's own capability)
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
from phi_redactor.redactor import redact  # noqa: E402

PHANTOM_STATUS_URL = "http://127.0.0.1:7878/api/status"


@dataclass
class Tool:
    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Callable[[Dict[str, Any]], Dict[str, Any]]


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
        return {"ok": False, "error": str(exc)}
    if proc.returncode != 0:
        return {"ok": False, "error": proc.stderr.strip()[:200] or "phantom recall failed"}
    try:
        results = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError as exc:
        return {"ok": False, "error": f"bad recall json: {exc}"}
    return {"ok": True, "query": query, "results": results}


def redact_phi(args: Dict[str, Any]) -> Dict[str, Any]:
    """De-identify PHI/PII in text via phi_redactor — the suite's own capability."""
    text = args.get("text", "")
    mode = args.get("mode", "replace")
    if not text:
        return {"ok": False, "error": "missing 'text' argument"}
    clean, mapping = redact(text, mode=mode)
    return {"ok": True, "redacted": clean, "count": len(mapping.items), "by_type": mapping.counters}


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
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return {"ok": False, "error": str(exc)}


# ----------------------------- server core ----------------------------------
DEFAULT_TOOLS: List[Tool] = [
    Tool(
        name="phantom_status",
        description="Get the local phantom coordinator status snapshot.",
        input_schema={"type": "object", "properties": {}, "required": []},
        handler=phantom_status,
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
    ),
]


@dataclass
class PhantomMCPServer:
    tools: List[Tool] = field(default_factory=lambda: list(DEFAULT_TOOLS))

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
                return {
                    "jsonrpc": "2.0",
                    "id": rid,
                    "error": {"code": -32601, "message": f"unknown tool {name!r}"},
                }
            result = tool.handler(args)
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        return {
            "jsonrpc": "2.0",
            "id": rid,
            "error": {"code": -32601, "message": f"unknown method {method!r}"},
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
