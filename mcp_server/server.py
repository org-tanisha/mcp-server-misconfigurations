from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_server.config import Settings
from mcp_server.tools import ToolRegistry


def build_server() -> FastMCP:
    settings = Settings.from_env()
    registry = ToolRegistry(settings)
    server = FastMCP("aws-misconfig-scanner")

    server.tool()(registry.scan_s3_misconfigurations)
    server.tool()(registry.scan_iam_misconfigurations)
    server.tool()(registry.scan_ec2_misconfigurations)
    server.tool()(registry.scan_rds_misconfigurations)
    server.tool()(registry.scan_security_groups)
    server.tool()(registry.scan_cloudtrail_status)
    server.tool()(registry.scan_all_resources)
    server.tool()(registry.scan_multiple_accounts)
    server.tool()(registry.generate_compliance_report)
    server.tool()(registry.generate_executive_summary)
    server.tool()(registry.generate_trend_report)
    return server
