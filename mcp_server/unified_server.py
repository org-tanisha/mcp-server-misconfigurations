from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_server.config import Settings
from mcp_server.tools import ToolRegistry
from mcp_server.nessus_tools import NessusToolRegistry


def build_unified_server() -> FastMCP:
    settings = Settings.from_env()
    registry = ToolRegistry(settings)
    nessus_registry = NessusToolRegistry(settings)
    
    server = FastMCP("security-scanner-unified")

    # AWS Tools
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
    server.tool()(registry.generate_jira_ticket_payload)
    server.tool()(registry.scan_and_generate_jira_payloads)
    
    # Nessus Specific Tools (some are redundant but kept for compatibility)
    server.tool()(nessus_registry.scan_onprem_infrastructure_nessus)
    server.tool()(nessus_registry.generate_onprem_nessus_report)
    
    return server
