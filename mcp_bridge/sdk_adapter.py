"""OPTIONAL adapter exposing the same tools via the official `mcp` Python SDK.

The core bridge is stdlib-only; this module is the ONLY place that touches the
SDK, and it is import-guarded so the core never depends on `mcp`. Install with
`pip install .[mcp-sdk]`. `tool_specs()` is pure (no SDK) so parity can be tested
with zero dependencies; `build_sdk_server()` requires the SDK."""
from __future__ import annotations

from typing import Any, Dict, List

from mcp_bridge.server import DEFAULT_TOOLS, PhantomMCPServer
from mcp_bridge.frameworks import frameworks_for_capabilities

try:  # the SDK is an optional extra; never let its absence break the core import
    import mcp  # noqa: F401
    SDK_AVAILABLE = True
except ImportError:
    SDK_AVAILABLE = False


def tool_specs() -> List[Dict[str, Any]]:
    """Canonical tool specs (name/description/inputSchema/capabilities/frameworks),
    derived from the hand-rolled DEFAULT_TOOLS. Pure — no SDK needed."""
    specs = []
    for t in DEFAULT_TOOLS:
        specs.append({
            "name": t.name,
            "description": t.description,
            "inputSchema": t.input_schema,
            "capabilities": sorted(c.value for c in t.capabilities),
            "frameworks": frameworks_for_capabilities(t.capabilities),
        })
    return specs


def build_sdk_server(policy: Any = None) -> Any:
    """Build an official-SDK MCP server exposing the same tools (with the capability
    gate). Raises if the SDK extra is not installed.

    NOTE: the SDK-specific wiring runs ONLY when `mcp` is installed (guarded by the
    skipif parity test). Verify the registration calls against the pinned SDK
    version when the extra is first installed."""
    if not SDK_AVAILABLE:
        raise RuntimeError(
            "official mcp SDK not installed; run: pip install .[mcp-sdk]"
        )
    from mcp.server.fastmcp import FastMCP  # type: ignore

    core = PhantomMCPServer(policy=policy) if policy is not None else PhantomMCPServer()
    app = FastMCP("phantom-secure-connector")
    for tool in core.tools:
        def _make(bound=tool):
            def _run(arguments: Dict[str, Any]) -> Dict[str, Any]:
                resp = core.handle({
                    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                    "params": {"name": bound.name, "arguments": arguments},
                })
                if "error" in resp:
                    return {"ok": False, "error": resp["error"]["message"]}
                return resp["result"]
            return _run
        app.add_tool(_make(), name=tool.name, description=tool.description)
    return app


def main() -> None:
    """Run the optional SDK-backed MCP server over stdio."""
    app = build_sdk_server()
    app.run()
