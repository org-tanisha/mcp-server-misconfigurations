from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_server.config import Settings
from mcp_server.nessus_tools import NessusToolRegistry

NESSUS_INSTRUCTIONS = """
Nessus Security Scanner

Purpose:
- Vulnerability triage for on-prem infrastructure
- Compliance reporting based on Nessus datasets
- Ticket payload generation

Safety Rules:
- Never modify infrastructure
- Use sample datasets for validation when possible
- Redaction is automatically applied to sensitive findings
"""

def build_nessus_server() -> FastMCP:
    settings = Settings.from_env()
    registry = NessusToolRegistry(settings)
    server = FastMCP(
        "nessus-onprem-scanner",
        instructions=NESSUS_INSTRUCTIONS
    )

    server.tool()(registry.scan_onprem_infrastructure_nessus)
    server.tool()(registry.generate_onprem_nessus_report)
    return server
