# AWS Misconfiguration Scanner (MCP)

AWS & Nessus Security Scanner MCP Server > 🛡️ An MCP-powered security auditor for Claude Desktop. Detects AWS misconfigurations (S3, IAM, EC2, RDS) and analyzes on-prem Nessus vulnerability data with CIS/NIST-aligned reporting.

This project is a Python AWS misconfiguration scanner exposed through MCP tools for Claude/Desktop clients.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
pytest -q
```

## Run

```powershell
.\.venv\Scripts\Activate.ps1
python main.py
```

For Claude Desktop:

```powershell
.\.venv\Scripts\Activate.ps1
python claude_launcher.py
```

Use the Claude Desktop MCP server names `aws-misconfig-scanner` and `nessus-onprem-scanner` (see `claude_desktop\claude_desktop_config.template.json`).
For a Nessus-only connector config, use `claude_desktop\nessus_claude_desktop_config.template.json` or run `python scripts\print_claude_nessus_config.py`.

## Core folders

- `mcp_server/`: MCP server bootstrap, config, and tool registry.
- `scanners/`: AWS service scanners (S3, IAM, EC2, Security Groups, RDS, CloudTrail, AWS Config) plus a separate on-prem Nessus dataset scanner.
- `rules/`: CIS/NIST/OWASP mappings, severity/risk scoring, and remediation metadata.
- `utils/`: AWS client factory, data models, reporting/history helpers.
- `tests/`: offline unit tests.

## MCP tools exposed

### `aws-misconfig-scanner`

- `scan_s3_misconfigurations`
- `scan_iam_misconfigurations`
- `scan_ec2_misconfigurations`
- `scan_rds_misconfigurations`
- `scan_security_groups`
- `scan_cloudtrail_status`
- `scan_all_resources`
- `scan_multiple_accounts`
- `generate_compliance_report`
- `generate_executive_summary`
- `generate_trend_report`

### `nessus-onprem-scanner`

- `scan_onprem_infrastructure_nessus`
- `generate_onprem_nessus_report`

## On-prem Nessus dataset connector

The `nessus-onprem-scanner` server reads a Nessus-style on-prem dataset and returns misconfiguration findings suitable for Claude Desktop.

Optional environment variables:

- `AWS_MCP_ENABLE_ONPREM_NESSUS=true` to enable Nessus dataset scanning.
- `AWS_MCP_ONPREM_DATASET_PATH=scanners\data\onprem_nessus_dataset.json` to override the default embedded dataset.
