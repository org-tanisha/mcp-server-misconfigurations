# AWS Misconfiguration & Nessus Security Scanner (MCP Server)

🛡️ **An MCP-powered security auditor for Claude Desktop.** 

Detects AWS misconfigurations across S3, IAM, EC2, RDS, and Security Groups. It also integrates on-prem Nessus vulnerability data and provides CIS/NIST-aligned reporting with Jira ticket generation capabilities.

---

## 🚀 Features

- **Multi-Service AWS Scanning:** Deep inspection of S3 buckets, IAM roles, EC2 instances, RDS databases, and Security Group rules.
- **On-Prem Nessus Integration:** Analyze vulnerability datasets from on-premise infrastructure.
- **Compliance Mapping:** Findings are mapped to CIS Controls, NIST CSF, and OWASP categories.
- **Jira Integration:** Generate ready-to-use JSON payloads for Jira ticket creation based on security findings.
- **Unified Server:** A single MCP server instance providing both AWS and Nessus tools.
- **Robust Launchers:** Production-ready launchers with enhanced logging and error handling.

---

## 🛠️ Setup

1. **Clone and Install Dependencies:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   ```

2. **Configure Environment:**
   ```powershell
   Copy-Item .env.example .env
   # Edit .env with your AWS credentials and preferences
   ```

3. **Verify Installation:**
   ```powershell
   pytest -q
   ```

---

## 🏃 Running the Server

### For Claude Desktop (Recommended)

To use with Claude Desktop, you can use the provided "robust" launchers which include better logging for debugging:

- **Unified (AWS + Nessus):**
  ```powershell
  python robust_unified_launcher.py
  ```
- **AWS Only:**
  ```powershell
  python robust_launcher.py
  ```
- **Nessus Only:**
  ```powershell
  python robust_nessus_launcher.py
  ```

### Manual/CLI Execution
```powershell
python main.py
```

---

## 📦 Core Architecture

- `mcp_server/`: MCP server implementations (`server.py`, `nessus_server.py`, `unified_server.py`).
- `scanners/`: AWS service-specific scanners and Nessus connector.
- `rules/`: Security rules, severity scoring, and compliance metadata (CIS/NIST).
- `utils/`: 
  - `jira.py`: Jira payload generation logic.
  - `reporting.py`: Compliance and executive report generation.
  - `aws_client.py`: AWS SDK wrappers.
- `scripts/`: Configuration templates and helper scripts for Claude Desktop.

---

## 🛠️ MCP Tools Exposed

### `security-scanner-unified` (Unified Server)

#### AWS Security Tools:
- `scan_s3_misconfigurations`: Detect public buckets, lack of encryption, and logging.
- `scan_iam_misconfigurations`: Identify over-privileged roles and users.
- `scan_ec2_misconfigurations`: Check for IMDSv1, unencrypted volumes, and public IPs.
- `scan_rds_misconfigurations`: Detect public databases and encryption status.
- `scan_security_groups`: Audit ingress rules for overly permissive ports (0.0.0.0/0).
- `scan_all_resources`: Comprehensive scan across all supported services.
- `generate_compliance_report`: Summary of findings mapped to CIS/NIST standards.

#### Jira Integration Tools:
- `generate_jira_ticket_payload`: Build a Jira JSON payload for a specific finding.
- `scan_and_generate_jira_payloads`: Run a scan and return all findings as Jira-ready payloads.

#### Nessus Tools:
- `scan_onprem_infrastructure_nessus`: Analyze on-prem vulnerability datasets.
- `generate_onprem_nessus_report`: Detailed reporting for Nessus findings.

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
