import pytest
pytest.importorskip("mcp")

from mcp_bridge.sdk_adapter import build_sdk_server, tool_specs


def test_mcp_server_builds_with_expected_tools():
    app = build_sdk_server()
    expected = {
        "phantom_status",
        "phantom_fts5_search",
        "phantom_event_capture",
        "redact_phi",
        "list_standards",
        "compliance_scan",
        "compliance_scan_file",
        "mask_text",
        "restore_text",
    }
    assert app is not None
    assert app.name == "phantom-secure-connector"
    assert {s["name"] for s in tool_specs()} == expected
