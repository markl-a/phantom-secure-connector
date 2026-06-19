# mcp_bridge — wire phantom-mesh into Claude Desktop / Cursor

> Usage doc for the MCP server. For project status / what's shipped, see
> [/docs/phantom-secure-connector.md](../docs/phantom-secure-connector.md).

A stdio MCP-style server exposing phantom + this suite's own engines:

| Tool | What it does |
|---|---|
| `phantom_status` | GET `http://127.0.0.1:7878/api/status` from the local phantom coordinator |
| `phantom_fts5_search` | Search phantom's event timeline via `phantom recall --json` |
| `phantom_event_capture` | Runs `phantom event capture --text <text>` via subprocess |
| `redact_phi` | De-identify PHI/PII via `phi_redactor` |
| `list_standards` | List compliance standards from `compliance_checker/rules/*.toml` |
| `compliance_scan` | Scan free text for compliance violations |
| `compliance_scan_file` | Scan a CSV/JSON file for compliance violations |
| `mask_text` | Reversibly tokenise PHI/PII, returning tokens + a server-side handle |
| `restore_text` | Byte-exact restore from a `mask_text` handle + tokenised text |

PHI is masked by default; `mask_text` returns only tokens (no raw PHI crosses
the wire) and the reverse map stays server-side for `restore_text`.

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

Restart Claude Desktop. The tools listed above should appear in the tool picker.

## Cursor / Codex

Same JSON block under their respective MCP server config sections. Cursor uses
`~/.cursor/mcp.json`.

## Manual smoke test

```bash
cd /Users/marklight/Documents/GitHub/phantom-secure-connector
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  python3 -m mcp_bridge.server
```

You should see a JSON response listing the tools.

## Roadmap

Planned bridge work (official `mcp` SDK migration, per-tool capability scoping,
etc.) is tracked centrally in [/docs/phantom-secure-connector.md](../docs/phantom-secure-connector.md).
