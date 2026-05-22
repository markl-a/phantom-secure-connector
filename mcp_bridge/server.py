"""Minimal MCP-style server stub exposing 3 phantom-mesh tools.

This is a Tier 1 skeleton: we model the MCP request/response surface
(tools/list, tools/call) over plain JSON-RPC so the wiring can be verified
without a hard dependency on ``mcp`` or ``fastmcp``. When Anthropic's spec
stabilises we will swap the transport for the official SDK.

Tools exposed:
- ``phantom_status``        — GET http://127.0.0.1:7878/api/status
- ``phantom_fts5_search``   — placeholder (returns canned result; Tier 2 hits
                              the real FTS5 index via phantom HTTP API)
- ``phantom_event_capture`` — subprocess ``phantom event capture <text>``

The server can be driven over stdio for Claude Desktop or imported as a
library for unit tests.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

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
    """Tier 1 placeholder. Tier 2: call phantom HTTP search endpoint."""
    query = args.get("query", "")
    return {
        "ok": True,
        "query": query,
        "results": [],
        "note": "Tier 1 placeholder — wire to phantom FTS5 in Tier 2",
    }


def phantom_event_capture(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run ``phantom event capture <text>`` if the phantom binary is in PATH."""
    text = args.get("text", "")
    if not text:
        return {"ok": False, "error": "missing 'text' argument"}
    phantom_bin = shutil.which("phantom")
    if not phantom_bin:
        return {"ok": False, "error": "phantom binary not in PATH"}
    try:
        proc = subprocess.run(
            [phantom_bin, "event", "capture", text],
            capture_output=True,
            text=True,
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
        description="Full-text search over the phantom event index (Tier 2).",
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
