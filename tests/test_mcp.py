"""
Pruebas unitarias para el Servidor MCP nativo JSON-RPC 2.0.
"""

from pathlib import Path
from sentinel.core.mcp_server import SentinelMCPServer


def test_mcp_server_initialize() -> None:
    server = SentinelMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }
    resp = server.handle_request(req)

    assert resp is not None
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "Antigravity Sentinel"


def test_mcp_server_tools_list() -> None:
    server = SentinelMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    resp = server.handle_request(req)

    assert resp is not None
    tools = resp["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "sentinel_scan" in tool_names
    assert "sentinel_sca" in tool_names
    assert "sentinel_explain" in tool_names
