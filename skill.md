# Skill: AWS and Nessus MCP Security Scanner

## Purpose
Guide an agent to use or extend an MCP server that scans AWS resources and Nessus datasets for security findings, maps them to compliance controls, and generates Jira-ready remediation payloads.

## When to Use
- Security posture reviews
- Misconfiguration audits
- Vulnerability triage
- Compliance reporting
- Ticket payload generation

## Discovery Questions
- Are we scanning a lab, dev, or production AWS account?
- Is access read-only?
- Are Nessus findings file-based or API-based?
- Should Jira payloads be generated only, or actually submitted outside MCP?
- Do users need single-service scans or full-environment scans?

## Deployment Guidance
- Default to local stdio for lab use
- Consider remote Streamable HTTP only after auth, logging, and tenant boundaries are defined

## Available Tools
- scan_s3_misconfigurations
- scan_iam_misconfigurations
- scan_ec2_misconfigurations
- scan_rds_misconfigurations
- scan_security_groups
- scan_all_resources
- generate_compliance_report
- scan_onprem_infrastructure_nessus
- generate_onprem_nessus_report
- generate_jira_ticket_payload
- scan_and_generate_jira_payloads

## Safety Rules
- Use least privilege AWS permissions
- Prefer read-only scanning
- Never modify resources
- Do not expose secrets in outputs (Redaction is automatically applied)
- Redact sensitive findings where needed
- Use sandbox/test Jira projects first

## Output Conventions
- Return structured findings with:
  - asset (resource_id)
  - issue
  - severity
  - evidence
  - remediation (remediation_steps)
  - compliance mappings (cis_control_id, nist_csf)
- Separate scan results from ticket payloads

## Validation and Testing
- Verify credentials before scanning
- Test each scanner independently
- Use sample datasets for Nessus validation
- Confirm Jira payload schema with sandbox issues

## Logging
- Log scan start/end
- Log service coverage
- Log errors without leaking credentials
- Log counts of findings by severity
