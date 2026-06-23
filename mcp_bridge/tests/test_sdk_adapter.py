import pytest
from mcp_bridge.sdk_adapter import SDK_AVAILABLE, tool_specs, build_sdk_server
from mcp_bridge.server import PhantomMCPServer


def test_tool_specs_match_server_names_and_schemas():
    specs = {s["name"]: s for s in tool_specs()}
    listed = PhantomMCPServer().handle({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    server_tools = {t["name"]: t for t in listed["result"]["tools"]}
    assert set(specs) == set(server_tools)
    for name, s in specs.items():
        assert s["inputSchema"] == server_tools[name]["inputSchema"]
        assert s["capabilities"] == server_tools[name]["capabilities"]


def test_build_sdk_server_unavailable_raises_clean():
    if SDK_AVAILABLE:
        pytest.skip("mcp SDK installed; unavailability path not exercised")
    with pytest.raises(RuntimeError) as ei:
        build_sdk_server()
    assert "mcp-sdk" in str(ei.value)


@pytest.mark.skipif(not SDK_AVAILABLE, reason="official mcp SDK not installed (core stays zero-dep)")
def test_sdk_server_exposes_identical_tool_names():
    srv = build_sdk_server()
    sdk_names = {s["name"] for s in tool_specs()}
    server_names = set(PhantomMCPServer().tool_names())
    assert sdk_names == server_names and srv is not None
