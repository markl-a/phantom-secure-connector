"""Tests for the MCP bridge skeleton — verifies tool registration + JSON-RPC."""
from __future__ import annotations

import json
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


def test_redact_phi_invalid_mode_returns_error_not_raise():
    """A bad ``mode`` from a remote tools/call must NOT raise an uncaught
    ValueError (which would crash the whole stdio serve loop) — it must come
    back as a clean error result the caller can read."""
    srv = PhantomMCPServer()
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 11, "method": "tools/call",
        "params": {"name": "redact_phi",
                   "arguments": {"text": "SSN 123-45-6789", "mode": "bogus"}},
    })
    r = resp["result"]
    assert r["ok"] is False
    assert "mode" in r["error"]
    # And no raw PHI leaked into the error payload.
    assert "123-45-6789" not in json.dumps(resp)


def test_handler_exception_becomes_jsonrpc_error_not_crash(monkeypatch):
    """If a tool handler raises unexpectedly, the server must convert it into a
    JSON-RPC error response rather than letting the exception escape and kill
    the serve loop. A bridge that crashes on one bad call denies service to
    every subsequent caller."""
    srv = PhantomMCPServer()

    def _boom(_args):
        raise RuntimeError("kaboom")

    # Replace a known tool's handler with one that explodes.
    tool = srv.find("redact_phi")
    monkeypatch.setattr(tool, "handler", _boom)
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 12, "method": "tools/call",
        "params": {"name": "redact_phi", "arguments": {"text": "hi"}},
    })
    assert "error" in resp
    assert resp["id"] == 12
    # Internal error code, with the message surfaced (not a raw traceback).
    assert resp["error"]["code"] == -32603
    assert "kaboom" in resp["error"]["message"]


def test_fts5_search_timeout_error_masks_phi_in_query(monkeypatch):
    """str(TimeoutExpired) embeds the full command line, which includes the
    caller's query — potential PHI. If `phantom recall` times out, the error
    returned to the client must mask that PHI, not echo the raw command."""
    import subprocess as sp

    import mcp_bridge.server as srv_mod

    monkeypatch.setattr(srv_mod.shutil, "which", lambda _n: "/usr/bin/phantom")

    def _boom(*a, **k):
        # Emulate a timeout whose str() echoes the argv (incl. the PHI query).
        raise sp.TimeoutExpired(
            cmd=["phantom", "recall", "patient SSN 123-45-6789", "--json"],
            timeout=15,
        )

    monkeypatch.setattr(srv_mod.subprocess, "run", _boom)
    out = srv_mod.phantom_fts5_search({"query": "patient SSN 123-45-6789"})
    assert out["ok"] is False
    # The raw SSN inside the echoed command line must be masked.
    assert "123-45-6789" not in json.dumps(out)


def test_event_capture_timeout_error_masks_phi(monkeypatch):
    """phantom_event_capture's TimeoutExpired str() includes '--text <PHI>';
    the returned error must mask it."""
    import subprocess as sp

    import mcp_bridge.server as srv_mod

    monkeypatch.setattr(srv_mod.shutil, "which", lambda _n: "/usr/bin/phantom")

    def _boom(*a, **k):
        raise sp.TimeoutExpired(
            cmd=["/usr/bin/phantom", "event", "capture", "--text", "DOB 1990-01-15"],
            timeout=5,
        )

    monkeypatch.setattr(srv_mod.subprocess, "run", _boom)
    out = srv_mod.phantom_event_capture({"text": "DOB 1990-01-15"})
    assert out["ok"] is False
    assert "1990-01-15" not in json.dumps(out)


def test_event_capture_stderr_is_masked(monkeypatch):
    """phantom_event_capture returns the child's stderr, which can echo the
    captured PHI text on error. The diagnostic stderr surface must be masked
    before it crosses the wire."""
    import types

    import mcp_bridge.server as srv_mod

    monkeypatch.setattr(srv_mod.shutil, "which", lambda _n: "/usr/bin/phantom")
    fake_proc = types.SimpleNamespace(
        returncode=1, stdout="captured", stderr="error capturing SSN 123-45-6789"
    )
    monkeypatch.setattr(srv_mod.subprocess, "run", lambda *a, **k: fake_proc)
    out = srv_mod.phantom_event_capture({"text": "SSN 123-45-6789"})
    assert "123-45-6789" not in json.dumps(out)


def test_unknown_tool_message_is_static_no_echo():
    """The unknown-tool error must be a STATIC message that never echoes the
    caller-controlled name (sounder than masking — a redactor can miss PHI)."""
    srv = PhantomMCPServer()
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 30, "method": "tools/call",
        "params": {"name": "weird name with junk", "arguments": {}},
    })
    assert "weird name with junk" not in json.dumps(resp)
    assert resp["error"]["code"] == -32601


def test_unknown_tool_name_does_not_leak_phi():
    """A caller-controlled tool ``name`` is echoed in the "unknown tool" error.
    If it carries PHI, that PHI crosses the wire in the error — the error
    channel must mask it like every other outbound surface."""
    srv = PhantomMCPServer()
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 20, "method": "tools/call",
        "params": {"name": "SSN 123-45-6789", "arguments": {}},
    })
    assert "error" in resp
    assert "123-45-6789" not in json.dumps(resp)


def test_unknown_method_name_does_not_leak_phi():
    """A caller-controlled ``method`` is echoed in the "unknown method" error;
    PHI in it must be masked, not forwarded raw."""
    srv = PhantomMCPServer()
    resp = srv.handle({"jsonrpc": "2.0", "id": 21, "method": "email a@b.com"})
    assert "error" in resp
    assert "a@b.com" not in json.dumps(resp)


def test_handler_error_message_does_not_leak_phi(monkeypatch):
    """If a handler raises with PHI echoed in its message (a realistic leaky
    bug), the JSON-RPC error returned to the remote client must NOT carry raw
    PHI. The error surface is part of the wire boundary — it must be redacted
    too, or this connector would have a PHI leak channel through exceptions.
    """
    srv = PhantomMCPServer()
    tool = srv.find("redact_phi")

    def _leaky(args):
        # A buggy handler that echoes its input into the exception message.
        raise ValueError(f"cannot parse {args['text']}")

    monkeypatch.setattr(tool, "handler", _leaky)
    resp = srv.handle({
        "jsonrpc": "2.0", "id": 13, "method": "tools/call",
        "params": {"name": "redact_phi",
                   "arguments": {"text": "SSN 123-45-6789 email a@b.com"}},
    })
    blob = json.dumps(resp)
    assert "error" in resp
    # The exception TYPE is still surfaced for debugging...
    assert "ValueError" in resp["error"]["message"]
    # ...but no raw PHI leaked through the error channel.
    assert "123-45-6789" not in blob
    assert "a@b.com" not in blob


def test_serve_stdio_survives_handler_error(monkeypatch):
    """End-to-end: feed serve_stdio a request that triggers a handler error
    followed by a valid request; the loop must answer BOTH (error then ok),
    proving one bad call does not tear down the server."""
    import io

    srv = PhantomMCPServer()
    tool = srv.find("redact_phi")
    calls = {"n": 0}
    real_handler = tool.handler

    def _flaky(args):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("first call boom")
        return real_handler(args)

    monkeypatch.setattr(tool, "handler", _flaky)

    req1 = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "redact_phi", "arguments": {"text": "SSN 123-45-6789"}}})
    req2 = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "redact_phi", "arguments": {"text": "SSN 123-45-6789"}}})
    monkeypatch.setattr(sys, "stdin", io.StringIO(req1 + "\n" + req2 + "\n"))
    out = io.StringIO()
    monkeypatch.setattr(sys, "stdout", out)
    srv.serve_stdio()
    lines = [json.loads(ln) for ln in out.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 2
    assert "error" in lines[0]          # first call errored cleanly
    assert lines[1]["result"]["ok"]     # second call succeeded — loop survived
    # No raw PHI leaked anywhere in the responses.
    assert "123-45-6789" not in out.getvalue()
