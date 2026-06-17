"""Tests for the MCP bridge skeleton — verifies tool registration + JSON-RPC."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mcp_bridge.server import PhantomMCPServer  # noqa: E402


def test_tools_registered():
    srv = PhantomMCPServer()
    names = srv.tool_names()
    assert set(names) == {
        "redact_phi",
        "phantom_status",
        "phantom_fts5_search",
        "phantom_event_capture",
    }


def test_tools_list_response_shape():
    srv = PhantomMCPServer()
    resp = srv.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert resp["id"] == 1
    assert "result" in resp
    tools = resp["result"]["tools"]
    assert len(tools) == 4
    for t in tools:
        assert "name" in t and "description" in t and "inputSchema" in t


def test_call_unknown_tool_returns_error():
    srv = PhantomMCPServer()
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "no_such_tool", "arguments": {}},
    })
    assert "error" in resp
    assert resp["error"]["code"] == -32601


def test_fts5_search_real_index():
    srv = PhantomMCPServer()
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "phantom_fts5_search", "arguments": {"query": "hi"}},
    })
    r = resp["result"]
    assert r["ok"] is True
    assert r["query"] == "hi"
    assert isinstance(r["results"], list)  # empty if store empty/absent — both fine


def test_redact_phi_masks_pii():
    srv = PhantomMCPServer()
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "redact_phi",
                   "arguments": {"text": "mail alice@example.com SSN 123-45-6789"}},
    })
    r = resp["result"]
    assert r["ok"] is True
    assert "alice@example.com" not in r["redacted"]
    assert r["count"] >= 2


def test_redact_phi_mask_mode_reports_count():
    """redact_phi in mask mode must still tell the caller how much PHI it
    stripped (count + by_type), not silently report zero. The masked output
    has no reverse map, but the audit metrics must be truthful."""
    srv = PhantomMCPServer()
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {"name": "redact_phi",
                   "arguments": {"text": "mail alice@example.com SSN 123-45-6789",
                                 "mode": "mask"}},
    })
    r = resp["result"]
    assert r["ok"] is True
    assert "alice@example.com" not in r["redacted"]
    assert "123-45-6789" not in r["redacted"]
    assert r["count"] == 2
    assert r["by_type"] == {"EMAIL": 1, "SSN": 1}


def test_phantom_status_handles_unreachable():
    # In a test env there's no phantom server on :7878 — handler must degrade
    # gracefully, not raise.
    srv = PhantomMCPServer()
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "phantom_status", "arguments": {}},
    })
    r = resp["result"]
    # Either ok (a real phantom is running) or graceful failure.
    assert isinstance(r, dict)
    assert "ok" in r
    if not r["ok"]:
        assert "error" in r


def test_event_capture_missing_text():
    srv = PhantomMCPServer()
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "phantom_event_capture", "arguments": {}},
    })
    r = resp["result"]
    assert r["ok"] is False
    assert "missing" in r["error"]


def test_unknown_method():
    srv = PhantomMCPServer()
    resp = srv.handle({"jsonrpc": "2.0", "id": 9, "method": "no/such"})
    assert "error" in resp
