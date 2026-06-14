"""MCP bridge — both ends of an MCP connection for the phantom suite.

- ``server`` exposes 4 phantom tools to an MCP host (Claude Desktop / Cursor):
  ``redact_phi``, ``phantom_status``, ``phantom_recall_search``,
  ``phantom_event_capture``.
- ``client`` connects OUT to an external MCP server and gates every tool call
  through a PHI-redaction guardrail + allowlist.

Stdlib-only, hand-rolled JSON-RPC over stdio (no ``mcp``/``fastmcp`` dependency
yet) so the wiring can be verified end-to-end before chasing full spec
compliance.
"""
from .server import (
    PhantomMCPServer,
    Tool,
    redact_phi,
    phantom_status,
    phantom_recall_search,
    phantom_event_capture,
)

__all__ = [
    "PhantomMCPServer",
    "Tool",
    "redact_phi",
    "phantom_status",
    "phantom_recall_search",
    "phantom_event_capture",
]
