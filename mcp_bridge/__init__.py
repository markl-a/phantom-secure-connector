"""MCP bridge — expose phantom-mesh tools to Claude Desktop / Cursor.

Tier 1 ships a stdlib-only MCP-style server skeleton. The protocol surface is
intentionally small (three tools) so we can verify wiring end-to-end before
chasing full MCP spec compliance.
"""
from .server import (
    PhantomMCPServer,
    Tool,
    phantom_status,
    phantom_fts5_search,
    phantom_event_capture,
)

__all__ = [
    "PhantomMCPServer",
    "Tool",
    "phantom_status",
    "phantom_fts5_search",
    "phantom_event_capture",
]
