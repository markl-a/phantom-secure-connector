# mcp_bridge — wire phantom-mesh into Claude Desktop / Cursor

Tier 1 ships a minimal stdio MCP-style server with three tools:

| Tool | What it does |
|---|---|
| `phantom_status` | GET `http://127.0.0.1:7878/api/status` from the local phantom coordinator |
| `phantom_fts5_search` | Placeholder; Tier 2 hits the real FTS5 search endpoint |
| `phantom_event_capture` | Runs `phantom event capture <text>` via subprocess |

## Claude Desktop config

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "phantom": {
      "command": "python3",
      "args": [
        "-m",
        "mcp_bridge.server"
      ],
      "cwd": "/Users/marklight/Documents/GitHub/phantom-secure-connector",
      "env": {}
    }
  }
}
```

Restart Claude Desktop. The three tools should appear in the tool picker.

## Cursor / Codex

Same JSON block under their respective MCP server config sections. Cursor uses
`~/.cursor/mcp.json`.

## Manual smoke test

```bash
cd /Users/marklight/Documents/GitHub/phantom-secure-connector
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  python3 -m mcp_bridge.server
```

You should see a JSON response listing the three tools.

## Roadmap

- Swap the hand-rolled JSON-RPC loop for the official `mcp` Python SDK once
  the spec stabilises (Anthropic is still iterating).
- Implement `phantom_fts5_search` against the phantom HTTP API.
- Add auth: today the bridge trusts whatever is on stdio. Production needs
  per-tool capability scoping aligned with phantom-mesh's cap system.
