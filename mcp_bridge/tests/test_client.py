"""Tests for the outbound MCP CLIENT security gate (mcp_bridge/client.py).

The transport (spawning a real external MCP server) is exercised manually in
the README demo against ``phantom mcp``. These tests pin the security gate —
the differentiator — without needing the phantom binary: PHI redaction of
arguments + allowlist enforcement, plus an in-process end-to-end against the
sibling ``PhantomMCPServer`` to prove the JSON-RPC handshake/framing works.
"""
import io
import json
import sys

from mcp_bridge.client import (
    DEFAULT_ALLOWLIST,
    MCPClientError,
    MCPStdioClient,
    _split_server_cmd,
    main,
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


# --------------------- transport framing (_read_response) -------------------
class _FakeProc:
    """Minimal stand-in for subprocess.Popen with a scripted stdout."""

    def __init__(self, lines):
        self.stdout = io.StringIO("".join(lines))
        self.stdin = io.StringIO()
        self.stderr = io.StringIO("")


def _client_with_stdout(lines):
    c = MCPStdioClient(server_cmd=["true"])
    c.proc = _FakeProc(lines)  # type: ignore[assignment]
    return c


def test_read_response_skips_notifications_and_mismatched_ids():
    """_read_response must skip interleaved notifications / out-of-order ids and
    return the response whose id matches, so framing stays correct even when a
    server emits notifications between requests."""
    c = _client_with_stdout([
        json.dumps({"jsonrpc": "2.0", "method": "notifications/progress"}) + "\n",
        json.dumps({"jsonrpc": "2.0", "id": 99, "result": {"stale": True}}) + "\n",
        "not json at all\n",
        "\n",
        json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}) + "\n",
    ])
    resp = c._read_response(1)
    assert resp["result"] == {"ok": True}


def test_read_response_raises_on_closed_stdout():
    """If the server closes stdout before answering, the client must raise a
    clear MCPClientError (not hang or return garbage)."""
    c = _client_with_stdout([])  # EOF immediately
    c._stderr_buf = ["boom: child crashed\n"]
    try:
        c._read_response(1)
    except MCPClientError as exc:
        assert "closed stdout" in str(exc)
        assert "boom" in str(exc)  # stderr tail surfaced for debugging
    else:  # pragma: no cover
        raise AssertionError("expected MCPClientError on closed stdout")


def test_start_spawn_failure_raises_clear_error():
    """Spawning a non-existent server binary must raise a clear MCPClientError
    naming the failed command, not a raw OSError."""
    client = MCPStdioClient(server_cmd=["this_binary_does_not_exist_42"])
    try:
        client.start()
    except MCPClientError as exc:
        assert "failed to spawn server" in str(exc)
    else:  # pragma: no cover
        client.close()
        raise AssertionError("expected MCPClientError on spawn failure")


def test_send_before_start_raises():
    c = MCPStdioClient(server_cmd=["true"])
    try:
        c._send({"jsonrpc": "2.0", "id": 1, "method": "ping"})
    except MCPClientError as exc:
        assert "not started" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected MCPClientError when proc not started")


# --------------------- cross-platform --server tokenising -------------------
def test_split_server_cmd_simple():
    assert _split_server_cmd("phantom mcp") == ["phantom", "mcp"]


def test_split_server_cmd_preserves_windows_path(monkeypatch):
    """A Windows-style path in --server must survive tokenising. Default POSIX
    shlex eats the backslashes (C:\\tools\\x.exe -> C:toolsx.exe); the splitter
    must use posix=False on nt. Regression for the cross-platform (P1) bug
    where a path-qualified server command was mangled into a bad executable."""
    monkeypatch.setattr("mcp_bridge.client.os.name", "nt")
    out = _split_server_cmd(r"C:\tools\phantom.exe mcp")
    assert out[0] == r"C:\tools\phantom.exe"
    assert out[1] == "mcp"
    # The backslashes are intact — not collapsed into "C:toolsphantom.exe".
    assert "\\" in out[0]


def test_split_server_cmd_posix_path(monkeypatch):
    monkeypatch.setattr("mcp_bridge.client.os.name", "posix")
    out = _split_server_cmd("/usr/local/bin/phantom mcp")
    assert out == ["/usr/local/bin/phantom", "mcp"]


def test_split_server_cmd_windows_quoted_path_with_spaces(monkeypatch):
    """A quoted Windows path containing spaces must tokenise to a clean argv
    element WITHOUT the literal wrapping quotes (which would otherwise fail as
    a subprocess argument). posix=False keeps the quotes; we strip them."""
    monkeypatch.setattr("mcp_bridge.client.os.name", "nt")
    out = _split_server_cmd(r'"C:\Program Files\phantom.exe" mcp')
    assert out[0] == r"C:\Program Files\phantom.exe"
    assert out[1] == "mcp"
    # No stray quote characters leaked into the executable token.
    assert '"' not in out[0]


def test_split_server_cmd_windows_quoted_option_value_with_spaces(monkeypatch):
    """A Windows command with an embedded quoted option value that contains
    spaces must tokenise correctly: --config="C:\\Program Files\\cfg.json"
    stays one argv element with backslashes intact and no stray quotes.
    Regression guard for the shlex posix/non-posix tradeoff."""
    monkeypatch.setattr("mcp_bridge.client.os.name", "nt")
    out = _split_server_cmd(r'cmd --config="C:\Program Files\cfg.json"')
    assert out == ["cmd", r"--config=C:\Program Files\cfg.json"]


def test_split_server_cmd_windows_bare_path(monkeypatch):
    monkeypatch.setattr("mcp_bridge.client.os.name", "nt")
    assert _split_server_cmd(r"C:\bin\phantom.exe mcp") == [r"C:\bin\phantom.exe", "mcp"]


def test_split_server_cmd_windows_single_quote_is_known_limitation(monkeypatch):
    """Documented limitation: a SINGLE-quoted Windows path is NOT supported on
    nt (backslashes survive doubled). This test pins the known behaviour so a
    future change is a conscious decision, not an accident. Use double quotes."""
    monkeypatch.setattr("mcp_bridge.client.os.name", "nt")
    out = _split_server_cmd(r"'C:\bin\x.exe' mcp")
    # Backslashes come out doubled — the documented limitation.
    assert out == [r"C:\\bin\\x.exe", "mcp"]


# ------------------------------- CLI surface --------------------------------
def test_main_bad_args_json_returns_2(capsys):
    rc = main(["--server", "true", "--call", "ls", "--args", "{not json}"])
    assert rc == 2
    assert "bad --args" in capsys.readouterr().err


def test_main_args_not_object_returns_2(capsys):
    rc = main(["--server", "true", "--call", "ls", "--args", "[1,2,3]"])
    assert rc == 2
    assert "bad --args" in capsys.readouterr().err


def test_main_empty_server_returns_2(capsys):
    rc = main(["--server", "   ", "--list"])
    assert rc == 2
    assert "server is empty" in capsys.readouterr().err


def test_main_list_against_in_proc_server(capsys):
    rc = main(["--server", f"{sys.executable} -m mcp_bridge.server", "--list"])
    assert rc == 0
    out = capsys.readouterr().out
    listed = json.loads(out)
    names = {t["name"] for t in listed}
    assert "redact_phi" in names


def test_main_call_redacts_phi_before_wire(capsys):
    """End-to-end through main(): a --call carrying PHI must have that PHI
    redacted by the gate before it reaches the (in-proc) server, and no raw
    PHI may appear in the result."""
    rc = main([
        "--server", f"{sys.executable} -m mcp_bridge.server",
        "--allow", "redact_phi",
        "--call", "redact_phi",
        "--args", json.dumps({"text": "SSN 123-45-6789"}),
    ])
    assert rc == 0
    captured = capsys.readouterr()
    assert "123-45-6789" not in captured.out


def test_main_call_blocked_tool_returns_1(capsys):
    """A tool not on the allowlist must be blocked, returning exit 1."""
    rc = main([
        "--server", f"{sys.executable} -m mcp_bridge.server",
        "--allow", "redact_phi",
        "--call", "phantom_status",
        "--args", "{}",
    ])
    assert rc == 1
    assert "blocked by allowlist" in capsys.readouterr().err


def test_main_nothing_to_do_returns_2(capsys):
    rc = main(["--server", f"{sys.executable} -m mcp_bridge.server"])
    assert rc == 2
    assert "nothing to do" in capsys.readouterr().err
