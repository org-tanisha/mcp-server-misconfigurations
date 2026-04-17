from __future__ import annotations

from utils.models import Finding


def map_severity_to_priority(severity: str) -> str:
    mapping = {
        "Critical": "Highest",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
    }
    return mapping.get(severity, "Medium")


def build_jira_payload(finding: Finding, project_key: str, issue_type: str) -> dict:
    summary = f"[AWS Security] {finding.service}: {finding.issue} on {finding.resource_id}"
    
    description = (
        f"h2. Finding Details\n"
        f"*Service:* {finding.service}\n"
        f"*Resource ID:* {finding.resource_id}\n"
        f"*Severity:* {finding.severity}\n"
        f"*Risk Score:* {finding.risk_score}\n\n"
        f"h2. Issue\n"
        f"{finding.issue}\n\n"
        f"h2. Risk Description\n"
        f"{finding.risk_description}\n\n"
        f"h2. Recommendation\n"
        f"{finding.recommendation}\n\n"
        f"h2. Remediation Steps\n"
    )
    for step in finding.remediation_steps:
        description += f"# {step}\n"
    
    description += (
        f"\nh2. Compliance Info\n"
        f"*CIS Control:* {finding.cis_control_id}\n"
        f"*Compliance Standard:* {finding.compliance_standard}\n"
    )
    if finding.nist_csf:
        description += f"*NIST CSF:* {', '.join(finding.nist_csf)}\n"
    if finding.owasp_category:
        description += f"*OWASP Category:* {finding.owasp_category}\n"

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
            "priority": {"name": map_severity_to_priority(finding.severity)},
            "labels": ["aws-security", finding.service.lower(), finding.severity.lower()]
        }
    }
    return payload
