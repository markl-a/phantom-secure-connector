"""Tests for the outbound MCP CLIENT security gate (mcp_bridge/client.py).

The transport (spawning a real external MCP server) is exercised manually in
the README demo against ``phantom mcp``. These tests pin the security gate —
the differentiator — without needing the phantom binary: PHI redaction of
arguments + allowlist enforcement, plus an in-process end-to-end against the
sibling ``PhantomMCPServer`` to prove the JSON-RPC handshake/framing works.
"""
import json
import sys

from mcp_bridge.client import (
    DEFAULT_ALLOWLIST,
    MCPClientError,
    MCPStdioClient,
    redact_arguments,
)


def test_redact_arguments_tokenises_nested_strings():
    args = {
        "key": "note",
        "value": "SSN 123-45-6789 email a@b.com",
        "meta": {"dob": "1980-04-12", "tags": ["clean", "phone 0912-345-678"]},
    }
    clean, n, by_type = redact_arguments(args)
    # 4 PHI items: SSN, EMAIL, DOB_ISO, TW_PHONE_M.
    assert n == 4
    assert by_type == {"SSN": 1, "EMAIL": 1, "DOB_ISO": 1, "TW_PHONE_M": 1}
    # No raw PHI survives anywhere in the outbound payload.
    blob = json.dumps(clean)
    for raw in ("123-45-6789", "a@b.com", "1980-04-12", "0912-345-678"):
        assert raw not in blob
    assert "[SSN_1]" in clean["value"]
    assert "[DOB_ISO_1]" in clean["meta"]["dob"]
    # Non-PHI structure preserved.
    assert clean["key"] == "note"
    assert clean["meta"]["tags"][0] == "clean"


def test_redact_arguments_noop_when_clean():
    clean, n, by_type = redact_arguments({"key": "hello", "value": "world"})
    assert n == 0
    assert by_type == {}
    assert clean == {"key": "hello", "value": "world"}


def test_allowlist_blocks_non_listed_tool():
    client = MCPStdioClient(server_cmd=["true"], allowlist=("memory_store",))
    # No process started; block must happen BEFORE any transport.
    try:
        client.call_tool("shell", {"command": "rm -rf /"})
    except MCPClientError as exc:
        assert "blocked by allowlist" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected allowlist block")


def test_default_allowlist_excludes_dangerous_tools():
    for dangerous in ("shell", "file_write", "git_commit", "bash_run_background"):
        assert dangerous not in DEFAULT_ALLOWLIST


def test_end_to_end_against_in_proc_server():
    """Spawn the sibling server.py as a subprocess and drive it through the
    real client (handshake + tools/list + gated tools/call). This exercises the
    JSON-RPC line framing without depending on the phantom binary."""
    cmd = [sys.executable, "-m", "mcp_bridge.server"]
    with MCPStdioClient(server_cmd=cmd, allowlist=("redact_phi",)) as client:
        tools = client.list_tools()
        names = {t["name"] for t in tools}
        assert "redact_phi" in names

        # Gated call: the value carries PHI; the gate tokenises before send.
        # redact_phi on the server then redacts the (already-tokenised) text.
        result = client.call_tool("redact_phi", {"text": "ping 8.8.8.8"})
        # Server returns its own redaction over the already-gate-redacted input.
        assert result.get("ok") is True
        # The IPv4 was redacted by the client gate before it ever reached server.
        assert "8.8.8.8" not in json.dumps(result)
