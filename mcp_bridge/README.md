# mcp_bridge — wire phantom-mesh into Claude Desktop / Cursor

Two sides:

- **`server.py`** — a stdio MCP-style server that *exposes* the phantom suite as
  tools to an MCP host (Claude Desktop / Cursor).
- **`client.py`** — an outbound MCP *client* that connects to an external MCP
  server and gates every `tools/call` through a PHI-redaction guardrail + a tool
  allowlist (see the repo root README for the client demo).

Both speak newline-delimited JSON over stdio. The transport is hand-rolled
JSON-RPC (no `mcp`/`fastmcp` dependency yet) — see Roadmap.

## Server tools (4)

| Tool | What it does |
|---|---|
| `redact_phi` | De-identify PHI/PII in text via this suite's `phi_redactor` |
| `phantom_status` | GET `http://127.0.0.1:7878/api/status` from the local phantom coordinator |
| `phantom_recall_search` | Search the phantom event timeline via `phantom recall --json` (decrypts `events/`) |
| `phantom_event_capture` | Run `phantom event capture --text <text>` via subprocess |

The phantom-backed tools (`phantom_status`, `phantom_recall_search`,
`phantom_event_capture`) shell out to a local `phantom` binary; when it is not on
`PATH` they degrade gracefully (empty result / error field) instead of raising.
`redact_phi` works with no external dependency.

> **Search path:** `phantom recall` is the supported read interface — it decrypts
> the per-event `events/` store. This is **not** backed by a live sqlite/FTS5
> index. (An `events.sqlite`/`fts5_events` table exists in phantom-mesh history
> as contentless scaffolding that was never synced; this bridge does not use it.)

## Claude Desktop config

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS).
Point `cwd` at wherever you cloned this repo:

```json
{
  "mcpServers": {
    "phantom": {
      "command": "python3",
      "args": [
        "-m",
        "mcp_bridge.server"
      ],
      "cwd": "/path/to/phantom-secure-connector",
      "env": {}
    }
  }
}
```

Restart Claude Desktop. The four tools should appear in the tool picker.

## Cursor / Codex

Same JSON block under their respective MCP server config sections. Cursor uses
`~/.cursor/mcp.json`.

## Manual smoke test

```bash
cd /path/to/phantom-secure-connector
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  python3 -m mcp_bridge.server
```

You should see a JSON response listing the four tools.

## Roadmap

- Swap the hand-rolled JSON-RPC loop for the official `mcp` Python SDK once
  the spec stabilises (Anthropic is still iterating).
- Add auth: today the bridge trusts whatever is on stdio. Production needs
  per-tool capability scoping aligned with phantom-mesh's cap system.
