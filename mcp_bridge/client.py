"""MCP CLIENT — securely connect OUT to an external MCP server, gating every
``tools/call`` through a PHI-redaction guardrail + tool allowlist.

This is the outbound counterpart to ``mcp_bridge/server.py`` (which *exposes*
the phantom suite as an MCP server). Here we *consume* an external MCP server:

    1. spawn it as a subprocess over stdio,
    2. do the MCP 2024-11-05 handshake  initialize -> notifications/initialized,
    3. discover its tools (tools/list),
    4. invoke a tool (tools/call) — BUT only after the security gate runs.

Security gate (the differentiator), applied before any payload crosses the
process boundary:
  (a) **PHI redaction** — every string value in the call arguments is run
      through ``phi_redactor.redact()`` so PHI is tokenised BEFORE it is sent
      to the external server. The external server never sees raw PHI.
  (b) **Allowlist enforcement** — only tool names on an explicit allowlist are
      forwarded; everything else is blocked locally and never reaches the wire.

For a fully-local, real demo the default external server is ``phantom mcp``
(a separate real MCP-server process). This is a genuine MCP client talking to a
separate MCP-server process over stdio — not an in-proc stub.

Reuses the JSON-RPC line framing convention from ``server.py`` (newline-
delimited JSON over stdio).

CLI:
    python3 -m mcp_bridge.client --server "phantom mcp" --list
    python3 -m mcp_bridge.client --server "phantom mcp" \
        --call memory_store --args '{"key":"note","value":"SSN 123-45-6789"}'
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Make the sibling phi_redactor importable when run as a module or a script.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phi_redactor.redactor import RedactionMap, redact  # noqa: E402
from secops_simulator import scan as scan_injection  # noqa: E402
from mcp_bridge.frameworks import frameworks_for_finding_family  # noqa: E402

MCP_PROTOCOL_VERSION = "2024-11-05"

# Default allowlist: read-mostly / safe tools. Override via --allow.
# These are the only tool names the gate will forward to the external server.
DEFAULT_ALLOWLIST: Tuple[str, ...] = (
    "memory_store",
    "memory_recall",
    "memory_list",
    "memory_search",
    "file_read",
    "ls",
    "stat",
    "content_search",
    "glob_search",
    "redact_phi",
    "phantom_status",
)


class MCPClientError(RuntimeError):
    """Raised on protocol / transport / gate failures."""


# --------------------------------------------------------------------------- #
# PHI gate
# --------------------------------------------------------------------------- #
def redact_arguments(args: Dict[str, Any]) -> Tuple[Dict[str, Any], int, Dict[str, int]]:
    """Walk every string in ``args`` (recursively) and redact PHI in place.

    Returns ``(clean_args, total_phi_items, by_type_counters)``. PHI is
    tokenised (``mode="replace"``) so the structure is preserved but no raw
    PHI value survives into the outbound payload.

    A SINGLE shared ``RedactionMap`` is used across the whole tree so that
    identical PHI maps to the same token everywhere and DISTINCT PHI maps to
    distinct tokens (``[SSN_1]``, ``[SSN_2]``…). This matters for dict keys:
    without a shared map, two different PHI keys would both tokenise to
    ``[SSN_1]`` and the second would clobber the first in the dict, silently
    dropping a value from the outbound payload. The tally is taken from the
    shared map's ``counters`` (the single source of truth) — accurate even
    under repeated/identical PHI.
    """
    mapping = RedactionMap()

    def _redact_str(value: str) -> str:
        clean, _ = redact(value, mode="replace", mapping=mapping)
        return clean

    def _walk(value: Any) -> Any:
        if isinstance(value, str):
            return _redact_str(value)
        if isinstance(value, dict):
            # Redact PHI in KEYS too — a key can carry a patient identifier and
            # would otherwise cross the process boundary unredacted. Non-string
            # keys (ints, etc.) pass through untouched. The shared map keeps
            # distinct PHI keys distinct, so no key collision drops a value.
            #
            # FAIL CLOSED on key collision: in the rare case two distinct source
            # keys redact to the same key (e.g. a pure-PHI key that tokenises to
            # exactly "[SSN_1]" alongside a literal "[SSN_1]" key), silently
            # keeping the last write would DROP an argument from the outbound
            # payload. A security gate must error rather than lose data.
            out_dict: Dict[Any, Any] = {}
            for k, v in value.items():
                new_k = _redact_str(k) if isinstance(k, str) else k
                if new_k in out_dict:
                    raise MCPClientError(
                        "PHI redaction produced a key collision "
                        f"({new_k!r}); refusing to silently drop an argument. "
                        "Rename the conflicting key before sending."
                    )
                out_dict[new_k] = _walk(v)
            return out_dict
        if isinstance(value, list):
            return [_walk(v) for v in value]
        return value

    clean_args = _walk(args)
    by_type: Dict[str, int] = dict(mapping.counters)
    total = sum(by_type.values())
    return clean_args, total, by_type


# --------------------------------------------------------------------------- #
# MCP client over stdio (reuses server.py's newline-delimited JSON framing)
# --------------------------------------------------------------------------- #
@dataclass
class MCPStdioClient:
    """Spawn an external MCP server as a subprocess and speak JSON-RPC to it.

    Newline-delimited JSON over stdio — the same framing convention used by
    ``server.PhantomMCPServer.serve_stdio``.
    """

    server_cmd: List[str]
    allowlist: Tuple[str, ...] = DEFAULT_ALLOWLIST
    timeout: float = 30.0
    scan_responses: bool = True
    scan_discovery: bool = True  # scan advertised tool name+description for poisoning
    scan_mode: str = "block"  # "block" | "warn"
    proc: Optional[subprocess.Popen] = field(default=None, init=False)
    _next_id: int = field(default=0, init=False)
    _stderr_buf: List[str] = field(default_factory=list, init=False)

    # ---- lifecycle ----
    def __enter__(self) -> "MCPStdioClient":
        self.start()
        self.initialize()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def start(self) -> None:
        try:
            self.proc = subprocess.Popen(
                self.server_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # line-buffered
            )
        except (OSError, FileNotFoundError) as exc:
            raise MCPClientError(f"failed to spawn server {self.server_cmd!r}: {exc}") from exc

        # Drain stderr in the background so the child never blocks on a full pipe.
        def _drain() -> None:
            assert self.proc and self.proc.stderr
            for line in self.proc.stderr:
                self._stderr_buf.append(line)

        threading.Thread(target=_drain, daemon=True).start()

    def close(self) -> None:
        if not self.proc:
            return
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    # ---- JSON-RPC framing (reused from server.py: newline-delimited JSON) ----
    def _new_id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _send(self, obj: Dict[str, Any]) -> None:
        if not self.proc or not self.proc.stdin:
            raise MCPClientError("server process not started")
        self.proc.stdin.write(json.dumps(obj) + "\n")
        self.proc.stdin.flush()

    def _read_response(self, expect_id: int) -> Dict[str, Any]:
        """Read newline-delimited JSON until we see the response with ``expect_id``.

        Skips notifications / mismatched ids (server may interleave them).
        """
        assert self.proc and self.proc.stdout
        while True:
            line = self.proc.stdout.readline()
            if line == "":
                stderr = "".join(self._stderr_buf)[-500:]
                raise MCPClientError(
                    f"server closed stdout before response id={expect_id}. "
                    f"stderr tail: {stderr!r}"
                )
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue  # ignore non-JSON log noise on stdout
            if msg.get("id") == expect_id:
                return msg
            # else: a notification or out-of-order message -> keep reading.

    def _request(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        rid = self._new_id()
        self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}})
        resp = self._read_response(rid)
        if "error" in resp:
            raise MCPClientError(f"{method} error: {resp['error']}")
        return resp.get("result", {})

    def _notify(self, method: str, params: Optional[Dict[str, Any]] = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    # ---- MCP methods ----
    def initialize(self) -> Dict[str, Any]:
        # Standard MCP 2024-11-05 handshake. Tolerate minimal servers that only
        # implement tools/list + tools/call and reject `initialize` (e.g. the
        # sibling server.py skeleton): the handshake is best-effort, the gate +
        # tools/call surface is what matters.
        try:
            result = self._request(
                "initialize",
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "phantom-secure-connector", "version": "0.1.0"},
                },
            )
        except MCPClientError as exc:
            print(f"[client] initialize not supported by server ({exc}); continuing", file=sys.stderr)
            return {}
        # Per MCP spec, follow up with the initialized notification.
        self._notify("notifications/initialized")
        return result

    def list_tools(self) -> List[Dict[str, Any]]:
        tools = self._request("tools/list").get("tools", [])
        if self.scan_discovery:
            self._scan_discovery(tools)
        return tools

    def _scan_discovery(self, tools: List[Dict[str, Any]]) -> None:
        """Scan each advertised tool's name+description for prompt-injection /
        tool-poisoning. block -> raise; warn -> log findings, return."""
        flagged: List[Tuple[str, List[Dict[str, Any]]]] = []
        for t in tools:
            text = f"{t.get('name', '')} {t.get('description', '')}"
            findings = scan_injection(text)
            if findings:
                masked = []
                for f in findings:
                    d = f.to_dict()
                    d["frameworks"] = frameworks_for_finding_family(d["family"])
                    masked.append(d)
                flagged.append((str(t.get("name", "")), masked))
        if not flagged:
            return
        for name, masked in flagged:
            print(
                f"[gate] discovery: tool {name!r} description flagged "
                f"{len(masked)} injection finding(s)",
                file=sys.stderr,
            )
        if self.scan_mode == "block":
            raise MCPClientError(
                f"tool-poisoning: {len(flagged)} advertised tool(s) carry "
                f"injection patterns: {dict(flagged)}"
            )

    def _scan_response(self, result: Any) -> List[Dict[str, Any]]:
        """Recursively scan every string field of a tool response for injection,
        returning masked findings each tagged with framework references. More
        precise than scanning one json.dumps blob."""
        findings_out: List[Dict[str, Any]] = []

        def _walk(value: Any) -> None:
            if isinstance(value, str):
                for f in scan_injection(value):
                    d = f.to_dict()
                    d["frameworks"] = frameworks_for_finding_family(d["family"])
                    findings_out.append(d)
            elif isinstance(value, dict):
                for v in value.values():
                    _walk(v)
            elif isinstance(value, list):
                for v in value:
                    _walk(v)

        _walk(result)
        return findings_out

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Invoke ``name`` on the external server — GATED.

        Gate order:
          1. allowlist check (block before anything crosses the boundary),
          2. PHI redaction of arguments (tokenise before send),
          3. inbound response prompt-injection scan.
        Emits human-readable gate lines to stderr so the security action is
        visible in demos.
        """
        # (b) allowlist enforcement — local block, never hits the wire.
        if name not in self.allowlist:
            print(
                f"[gate] tool {name!r} BLOCKED (not in allowlist: "
                f"{', '.join(self.allowlist)})",
                file=sys.stderr,
            )
            raise MCPClientError(f"tool {name!r} blocked by allowlist")
        print(f"[gate] tool {name!r} ALLOWED", file=sys.stderr)

        # (a) PHI redaction — tokenise BEFORE the payload crosses the boundary.
        clean_args, n_phi, by_type = redact_arguments(arguments)
        if n_phi:
            detail = ", ".join(f"{k}={v}" for k, v in sorted(by_type.items()))
            print(
                f"[gate] redacted {n_phi} PHI item(s) before send ({detail})",
                file=sys.stderr,
            )
            print(f"[gate] raw args (local only) : {json.dumps(arguments)}", file=sys.stderr)
            print(f"[gate] sent args (redacted)  : {json.dumps(clean_args)}", file=sys.stderr)
        else:
            print("[gate] redacted 0 PHI item(s) before send", file=sys.stderr)

        result = self._request("tools/call", {"name": name, "arguments": clean_args})
        if self.scan_responses:
            findings = self._scan_response(result)
            if findings:
                print(
                    f"[gate] inbound injection flagged: {len(findings)} finding(s) in "
                    f"response from tool {name!r}",
                    file=sys.stderr,
                )
                if self.scan_mode == "block":
                    raise MCPClientError(
                        f"inbound injection flagged {len(findings)} finding(s) "
                        f"in response from tool {name!r}: {findings}"
                    )
                if isinstance(result, dict):
                    result["_injection_findings"] = findings
                else:
                    result = {"result": result, "_injection_findings": findings}

        return result


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="phantom-secure-connector",
        description=(
            "MCP CLIENT: connect OUT to an external MCP server over stdio and "
            "gate tool calls through a PHI-redaction guardrail + allowlist."
        ),
    )
    p.add_argument(
        "--server",
        default="phantom mcp",
        help="external MCP server command to spawn (default: 'phantom mcp')",
    )
    p.add_argument("--list", action="store_true", help="list the external server's tools and exit")
    p.add_argument("--call", metavar="TOOL", help="tool name to invoke on the external server")
    p.add_argument("--args", default="{}", help="JSON object of arguments for --call")
    p.add_argument(
        "--allow",
        help="comma-separated tool allowlist (overrides the built-in default)",
    )
    p.add_argument("--timeout", type=float, default=30.0, help="per-request timeout seconds")
    return p


def _split_server_cmd(server: str) -> List[str]:
    """Tokenise the ``--server`` command string in a cross-platform way.

    ``shlex.split`` defaults to POSIX mode, which treats ``\\`` as an escape and
    DESTROYS Windows paths (``C:\\tools\\phantom.exe`` -> ``C:toolsphantom.exe``).
    The repo targets identical behaviour on Mac/Windows/Linux.

    On Windows we double the backslashes BEFORE a POSIX split, so they survive
    as literal path separators while POSIX quoting/spaces still work correctly.
    This beats ``posix=False`` (which leaves wrapping quotes on tokens AND
    mis-splits an embedded quoted option value like
    ``--config="C:\\Program Files\\cfg.json"``). Examples, all correct:

        phantom mcp                                  -> [phantom, mcp]
        C:\\tools\\phantom.exe mcp                     -> [C:\\tools\\phantom.exe, mcp]
        "C:\\Program Files\\x.exe" mcp                 -> [C:\\Program Files\\x.exe, mcp]
        cmd --config="C:\\Program Files\\cfg.json"     -> [cmd, --config=C:\\Program Files\\cfg.json]

    KNOWN LIMITATION (intentional, not a platform claim): on Windows, wrap a
    path-with-spaces in DOUBLE quotes. SINGLE-quoted wrapping (which PowerShell
    does accept) is not supported here — a backslash inside a POSIX
    single-quoted span is not unescaped, so the pre-doubling leaves it doubled.
    Supporting it would need a full Win32 command-line parser; the connector's
    ``--server`` is a command plus simple args, so we accept this limitation
    rather than over-engineer. Bare paths, double-quoted paths, and
    double-quoted option values all tokenise correctly.
    """
    if os.name == "nt":
        server = server.replace("\\", "\\\\")
    return shlex.split(server, posix=True)


def main(argv: Optional[List[str]] = None) -> int:
    args = _build_parser().parse_args(argv)

    server_cmd = _split_server_cmd(args.server)
    if not server_cmd:
        print("error: --server is empty", file=sys.stderr)
        return 2

    allowlist = (
        tuple(s.strip() for s in args.allow.split(",") if s.strip())
        if args.allow
        else DEFAULT_ALLOWLIST
    )

    try:
        call_args = json.loads(args.args)
        if not isinstance(call_args, dict):
            raise ValueError("--args must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"error: bad --args: {exc}", file=sys.stderr)
        return 2

    try:
        with MCPStdioClient(server_cmd, allowlist=allowlist, timeout=args.timeout) as client:
            print(f"[client] connected to external MCP server: {' '.join(server_cmd)}", file=sys.stderr)

            if args.list:
                tools = client.list_tools()
                print(f"[client] external server exposes {len(tools)} tool(s):", file=sys.stderr)
                out = [{"name": t.get("name"), "description": t.get("description", "")} for t in tools]
                print(json.dumps(out, indent=2))
                return 0

            if args.call:
                tools = client.list_tools()
                names = {t.get("name") for t in tools}
                if args.call not in names:
                    print(
                        f"[client] warning: {args.call!r} not advertised by server "
                        f"(server has {len(names)} tools)",
                        file=sys.stderr,
                    )
                result = client.call_tool(args.call, call_args)
                print(json.dumps(result, indent=2))
                return 0

            print("nothing to do: pass --list or --call <tool>", file=sys.stderr)
            return 2
    except MCPClientError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
