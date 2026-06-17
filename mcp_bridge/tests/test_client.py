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


def test_redact_arguments_redacts_phi_in_dict_keys():
    """PHI can appear in a dict KEY, not just a value (e.g. a caller that uses
    a patient identifier as a map key). The gate must redact keys too —
    otherwise raw PHI in a key crosses the process boundary to the external
    MCP server. This is a leak path: the whole point of the gate is that no
    raw PHI value survives into the outbound payload, anywhere.
    """
    args = {"patient SSN 123-45-6789": {"email a@b.com": "note"}}
    clean, n, by_type = redact_arguments(args)
    blob = json.dumps(clean)
    # No raw PHI survives in keys OR values.
    assert "123-45-6789" not in blob
    assert "a@b.com" not in blob
    # The key PHI is counted in the tally (truthful audit).
    assert n >= 2
    assert by_type.get("SSN") == 1
    assert by_type.get("EMAIL") == 1


def test_redact_arguments_nonstring_keys_preserved():
    """Non-string keys (ints) must pass through untouched, not crash."""
    args = {1: "SSN 123-45-6789", 2: "clean"}
    clean, n, by_type = redact_arguments(args)
    assert set(clean.keys()) == {1, 2}
    assert "123-45-6789" not in json.dumps({str(k): v for k, v in clean.items()})
    assert n == 1


def test_redact_arguments_distinct_phi_keys_do_not_collide():
    """Two DISTINCT PHI keys must redact to DISTINCT tokens — otherwise the
    dict comprehension silently clobbers one value (data loss in the outbound
    payload). A shared redaction map gives [SSN_1] and [SSN_2], preserving
    both entries. Regression for the key-collision clobber bug.
    """
    args = {"SSN 111-22-3333": "valueA", "SSN 444-55-6666": "valueB"}
    clean, n, by_type = redact_arguments(args)
    # Both values survive — no key collision dropped an entry.
    assert len(clean) == 2
    assert set(clean.values()) == {"valueA", "valueB"}
    # Distinct PHI -> distinct tokens.
    assert set(clean.keys()) == {"SSN [SSN_1]", "SSN [SSN_2]"}
    # No raw PHI in keys.
    blob = json.dumps(clean)
    assert "111-22-3333" not in blob and "444-55-6666" not in blob
    assert by_type.get("SSN") == 2


def test_redact_arguments_key_collision_fails_closed():
    """A PHI gate must FAIL CLOSED, never silently drop data. If two distinct
    source keys map to the same redacted key — e.g. a pure-PHI key ``123-45-6789``
    redacts to ``[SSN_1]`` while another key is literally ``[SSN_1]`` — the dict
    comprehension would otherwise drop one value from the OUTBOUND payload. A
    security gate that silently loses arguments is worse than one that errors:
    the caller must know the payload could not be safely formed.
    """
    import pytest

    args = {"123-45-6789": "valueA", "[SSN_1]": "valueB"}
    with pytest.raises(MCPClientError) as exc:
        redact_arguments(args)
    assert "collision" in str(exc.value).lower()


def test_redact_arguments_same_phi_repeated_uses_one_token():
    """Identical PHI repeated across fields/keys reuses ONE token (idempotent),
    so the forwarded payload is consistent."""
    args = {"id SSN 123-45-6789": "x", "note": "again SSN 123-45-6789"}
    clean, n, by_type = redact_arguments(args)
    blob = json.dumps(clean)
    assert "123-45-6789" not in blob
    # Same SSN -> same token everywhere.
    assert blob.count("[SSN_1]") == 2
    assert "[SSN_2]" not in blob
    assert by_type.get("SSN") == 1


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
