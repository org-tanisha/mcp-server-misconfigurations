from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_server.config import Settings
from mcp_server.tools import ToolRegistry

AWS_INSTRUCTIONS = """
AWS Security Scanner

Purpose:
- Security posture reviews for AWS resources (S3, IAM, EC2, RDS, etc.)
- Misconfiguration audits
- Compliance reporting (CIS, NIST)

Safety Rules:
- Use least privilege AWS permissions
- Prefer read-only scanning
- Never modify resources
- Redaction is automatically applied to sensitive findings
"""

def build_server() -> FastMCP:
    settings = Settings.from_env()
    registry = ToolRegistry(settings)
    server = FastMCP(
        "aws-misconfig-scanner",
        instructions=AWS_INSTRUCTIONS
    )

    server.tool()(registry.scan_s3_misconfigurations)
    server.tool()(registry.scan_iam_misconfigurations)
    server.tool()(registry.scan_ec2_misconfigurations)
    server.tool()(registry.scan_rds_misconfigurations)
    server.tool()(registry.scan_security_groups)
    server.tool()(registry.scan_cloudtrail_status)
    server.tool()(registry.scan_onprem_nessus_vulnerabilities)
    server.tool()(registry.scan_all_resources)
    server.tool()(registry.scan_multiple_accounts)
    server.tool()(registry.generate_compliance_report)
    server.tool()(registry.generate_executive_summary)
    server.tool()(registry.generate_trend_report)
    server.tool()(registry.generate_jira_ticket_payload)
    server.tool()(registry.scan_and_generate_jira_payloads)
    return server
