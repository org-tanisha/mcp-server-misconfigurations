from __future__ import annotations

from pathlib import Path

from rules.cis_rules import build_finding
from utils.reporting import build_executive_summary, build_report_payload, write_executive_summary_markdown


def sample_findings():
    return [
        build_finding(
            service="Amazon S3",
            resource_id="bucket-1",
            issue="Publicly Accessible Bucket",
            rule_key="s3_public_bucket",
            risk_description="Public access may expose sensitive financial data.",
        ),
        build_finding(
            service="AWS CloudTrail",
            resource_id="account",
            issue="CloudTrail Logging Disabled",
            rule_key="cloudtrail_disabled",
            risk_description="Logging gaps reduce detection capability.",
        ),
        build_finding(
            service="IAM",
            resource_id="alice",
            issue="IAM User Without MFA",
            rule_key="iam_user_without_mfa",
            risk_description="Missing MFA increases account takeover risk.",
        ),
    ]


def test_build_report_payload_includes_breakdowns():
    payload = build_report_payload(sample_findings())
    assert payload["finding_count"] == 3
    assert payload["breakdowns"]["severity"]["Critical"] == 1
    assert payload["breakdowns"]["service"]["Amazon S3"] == 1
    assert "summary" in payload
    assert len(payload["top_findings"]) > 0


def test_executive_summary_contains_rollups():
    summary = build_executive_summary(sample_findings())
    assert summary.critical_findings == 1
    assert summary.high_findings == 2
    assert summary.service_breakdown["IAM"] == 1
    assert len(summary.top_risks) == 3


def test_write_executive_summary_markdown_creates_file(tmp_path: Path):
    summary = build_executive_summary(sample_findings())
    path = write_executive_summary_markdown(tmp_path / "executive.md", summary)
    content = path.read_text(encoding="utf-8")
    assert "# Executive Summary" in content
    assert "Critical findings" in content

