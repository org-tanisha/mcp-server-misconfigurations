from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from mcp_server.config import Settings
from mcp_server.tools import ToolRegistry
from mcp_server.nessus_tools import NessusToolRegistry


UNIFIED_INSTRUCTIONS = """
AWS and Nessus MCP Security Scanner

Purpose:
- Security posture reviews
- Misconfiguration audits
- Vulnerability triage
- Compliance reporting
- Ticket payload generation

Safety Rules:
- Use least privilege AWS permissions
- Prefer read-only scanning
- Never modify resources
- Do not expose secrets in outputs (Redaction is automatically applied)
- Redact sensitive findings where needed
- Use sandbox/test Jira projects first

Output Conventions:
- Return structured findings with: asset (resource_id), issue, severity, evidence, remediation (remediation_steps), compliance mappings (cis_control_id, nist_csf)
- Separate scan results from ticket payloads

Logging:
- Scan start/end is logged
- Service coverage is logged
- Errors are logged without leaking credentials
- Counts of findings by severity are logged
"""

def build_unified_server() -> FastMCP:
    settings = Settings.from_env()
    registry = ToolRegistry(settings)
    nessus_registry = NessusToolRegistry(settings)
    
    server = FastMCP(
        "security-scanner-unified",
        instructions=UNIFIED_INSTRUCTIONS
    )

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
    
    # Nessus Specific Tools
    server.tool()(nessus_registry.scan_onprem_infrastructure_nessus)
    server.tool()(nessus_registry.generate_onprem_nessus_report)
    
    return server
