from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_server.config import Settings
from mcp_server.nessus_tools import NessusToolRegistry


def build_nessus_server() -> FastMCP:
    settings = Settings.from_env()
    registry = NessusToolRegistry(settings)
    server = FastMCP("nessus-onprem-scanner")

    server.tool()(registry.scan_onprem_infrastructure_nessus)
    server.tool()(registry.generate_onprem_nessus_report)
    return server
