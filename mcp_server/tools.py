from __future__ import annotations

from pathlib import Path

from mcp_server.config import Settings
from scanners.config_scanner import AWSConfigScanner
from scanners.cloudtrail_scanner import CloudTrailScanner
from scanners.ec2_scanner import EC2Scanner
from scanners.iam_scanner import IAMScanner
from scanners.nessus_scanner import NessusOnPremScanner
from scanners.rds_scanner import RDSScanner
from scanners.s3_scanner import S3Scanner
from scanners.security_group_scanner import SecurityGroupScanner
from utils.jira import build_jira_payload
from utils.models import Finding
from utils.reporting import (
    build_trend_report,
    build_executive_summary,
    load_history_records,
    persist_scan_history,
    write_executive_summary_markdown,
    write_json_report,
    write_markdown_report,
)


class ToolRegistry:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _annotate_findings(self, findings: list[Finding], profile_name: str | None) -> list[Finding]:
        if not profile_name:
            return findings
        annotated = []
        for finding in findings:
            metadata = dict(finding.metadata)
            metadata["aws_profile"] = profile_name
            annotated.append(finding.model_copy(update={"metadata": metadata}))
        return annotated

    def _scan_all_findings(self, settings: Settings | None = None) -> list[Finding]:
        active_settings = settings or self.settings
        findings: list[Finding] = []
        scanners = [
            S3Scanner(active_settings),
            IAMScanner(active_settings),
            EC2Scanner(active_settings),
            RDSScanner(active_settings),
            SecurityGroupScanner(active_settings),
            CloudTrailScanner(active_settings),
        ]
        if active_settings.enable_aws_config:
            scanners.append(AWSConfigScanner(active_settings))
        if active_settings.enable_onprem_nessus:
            scanners.append(NessusOnPremScanner(active_settings))
        for scanner in scanners:
            findings.extend(scanner.scan().findings)
        return self._annotate_findings(findings, active_settings.aws_profile)

    def _history_file(self, prefix: str) -> Path:
        timestamp = __import__("datetime").datetime.now(__import__("datetime").UTC).strftime("%Y%m%dT%H%M%SZ")
        return Path(self.settings.history_dir) / f"{prefix}_{timestamp}.json"

    def scan_s3_misconfigurations(self) -> list[dict]:
        return [item.model_dump() for item in S3Scanner(self.settings).scan().findings]

    def scan_iam_misconfigurations(self) -> list[dict]:
        return [item.model_dump() for item in IAMScanner(self.settings).scan().findings]

    def scan_ec2_misconfigurations(self) -> list[dict]:
        findings = EC2Scanner(self.settings).scan().findings
        findings.extend(SecurityGroupScanner(self.settings).scan().findings)
        return [item.model_dump() for item in findings]

    def scan_rds_misconfigurations(self) -> list[dict]:
        return [item.model_dump() for item in RDSScanner(self.settings).scan().findings]

    def scan_security_groups(self) -> list[dict]:
        return [item.model_dump() for item in SecurityGroupScanner(self.settings).scan().findings]

    def scan_cloudtrail_status(self) -> list[dict]:
        return [item.model_dump() for item in CloudTrailScanner(self.settings).scan().findings]

    def scan_onprem_nessus_vulnerabilities(self) -> list[dict]:
        return [item.model_dump() for item in NessusOnPremScanner(self.settings).scan().findings]

    def scan_all_resources(self) -> list[dict]:
        return [item.model_dump() for item in self._scan_all_findings()]

    def scan_multiple_accounts(self) -> dict:
        profiles = self.settings.aws_profiles or ([self.settings.aws_profile] if self.settings.aws_profile else [])
        results = []
        all_findings: list[Finding] = []
        for profile in profiles:
            scoped_settings = self.settings.model_copy(update={"aws_profile": profile})
            findings = self._scan_all_findings(scoped_settings)
            results.append(
                {
                    "aws_profile": profile,
                    "finding_count": len(findings),
                    "findings": [item.model_dump() for item in findings],
                }
            )
            all_findings.extend(findings)
        history_path = persist_scan_history(
            self._history_file("multi_account_scan"),
            all_findings,
            scope="multi-account",
        )
        return {
            "profiles_scanned": profiles,
            "account_count": len(profiles),
            "finding_count": len(all_findings),
            "history_record": str(history_path),
            "results": results,
        }

    def generate_compliance_report(self) -> dict:
        findings = self._scan_all_findings()
        json_path = write_json_report(Path(self.settings.output_dir) / "compliance_report.json", findings)
        markdown_path = write_markdown_report(Path(self.settings.output_dir) / "compliance_report.md", findings)
        history_path = persist_scan_history(
            self._history_file("compliance_report"),
            findings,
            scope=self.settings.aws_profile or "single-account",
        )
        return {
            "json_report": str(json_path),
            "markdown_report": str(markdown_path),
            "finding_count": len(findings),
            "history_record": str(history_path),
        }

    def generate_executive_summary(self) -> dict:
        findings = self._scan_all_findings()
        summary = build_executive_summary(findings)
        markdown_path = write_executive_summary_markdown(
            Path(self.settings.output_dir) / "executive_summary.md",
            summary,
        )
        return {
            "report_path": str(markdown_path),
            "summary": summary.model_dump(),
        }

    def generate_trend_report(self) -> dict:
        records = load_history_records(Path(self.settings.history_dir))
        return build_trend_report(records)

    def generate_jira_ticket_payload(self, finding_data: dict) -> dict:
        finding = Finding.model_validate(finding_data)
        return build_jira_payload(
            finding,
            self.settings.jira_project_key,
            self.settings.jira_issue_type,
        )

    def scan_and_generate_jira_payloads(self) -> list[dict]:
        findings = self._scan_all_findings()
        return [
            build_jira_payload(
                finding,
                self.settings.jira_project_key,
                self.settings.jira_issue_type,
            )
            for finding in findings
        ]
