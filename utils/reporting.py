from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
import json

from utils.models import ExecutiveSummary, Finding


def _severity_order(value: str) -> tuple[int, str]:
    rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return (rank.get(value, 99), value)


def _service_breakdown(findings: list[Finding]) -> dict[str, int]:
    return dict(sorted(Counter(finding.service for finding in findings).items()))


def _severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    counts = Counter(finding.severity for finding in findings)
    return {severity: counts[severity] for severity in sorted(counts, key=_severity_order)}


def _compliance_breakdown(findings: list[Finding]) -> dict[str, int]:
    return dict(sorted(Counter(finding.cis_control_id for finding in findings).items()))


def _top_findings(findings: list[Finding], limit: int = 5) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (_severity_order(item.severity), -item.risk_score, item.issue),
    )[:limit]


def build_executive_summary(findings: list[Finding]) -> ExecutiveSummary:
    counts = Counter(finding.severity for finding in findings)
    top_risks = [
        f"{finding.severity}: {finding.issue} ({finding.service})"
        for finding in sorted(
            findings,
            key=lambda item: (_severity_order(item.severity), -item.risk_score, item.issue),
        )[:3]
    ]
    compliance_gaps = sorted({finding.cis_control_id for finding in findings})
    service_breakdown = _service_breakdown(findings)
    severity_breakdown = _severity_breakdown(findings)
    summary = (
        "The scan identified AWS configuration issues that increase exposure to data loss, "
        "unauthorized access, and audit findings. Priority should be given to internet-exposed "
        "resources, weak IAM controls, and logging gaps."
    )
    return ExecutiveSummary(
        total_findings=len(findings),
        critical_findings=counts.get("Critical", 0),
        high_findings=counts.get("High", 0),
        medium_findings=counts.get("Medium", 0),
        low_findings=counts.get("Low", 0),
        top_risks=top_risks,
        compliance_gaps=compliance_gaps,
        service_breakdown=service_breakdown,
        severity_breakdown=severity_breakdown,
        summary=summary,
    )


def build_report_payload(findings: list[Finding]) -> dict:
    summary = build_executive_summary(findings)
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "finding_count": len(findings),
        "summary": summary.model_dump(),
        "breakdowns": {
            "severity": _severity_breakdown(findings),
            "service": _service_breakdown(findings),
            "cis_controls": _compliance_breakdown(findings),
        },
        "top_findings": [finding.model_dump() for finding in _top_findings(findings)],
        "findings": [finding.model_dump() for finding in findings],
    }


def write_json_report(path: Path, findings: list[Finding]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_report_payload(findings)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_markdown_report(path: Path, findings: list[Finding]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    summary = build_executive_summary(findings)
    lines = [
        "# AWS Misconfiguration Report",
        "",
        f"Generated at: {datetime.now(UTC).isoformat()}",
        "",
        "## Executive Summary",
        "",
        summary.summary,
        "",
        f"- Total findings: {summary.total_findings}",
        f"- Critical: {summary.critical_findings}",
        f"- High: {summary.high_findings}",
        f"- Medium: {summary.medium_findings}",
        f"- Low: {summary.low_findings}",
        "",
        "## Severity Breakdown",
        "",
    ]
    for severity, count in summary.severity_breakdown.items():
        lines.append(f"- {severity}: {count}")
    lines.extend(["", "## Service Breakdown", ""])
    for service, count in summary.service_breakdown.items():
        lines.append(f"- {service}: {count}")
    lines.extend(["", "## CIS Control Gaps", ""])
    for control_id in summary.compliance_gaps:
        lines.append(f"- {control_id}")
    lines.extend(["", "## Top Risks", ""])
    for item in _top_findings(findings):
        lines.extend(
            [
                f"### {item.issue}",
                f"- Service: {item.service}",
                f"- Resource: {item.resource_id}",
                f"- Severity: {item.severity}",
                f"- CIS Control: {item.cis_control_id}",
                f"- Risk Score: {item.risk_score}",
                f"- Recommendation: {item.recommendation}",
                "",
            ]
        )
    lines.extend(["## Full Findings", ""])
    for finding in findings:
        lines.extend(
            [
                f"### {finding.issue}",
                f"- Service: {finding.service}",
                f"- Resource: {finding.resource_id}",
                f"- Severity: {finding.severity}",
                f"- CIS Control: {finding.cis_control_id}",
                f"- Risk Score: {finding.risk_score}",
                f"- Recommendation: {finding.recommendation}",
                "",
            ]
        )
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_executive_summary_markdown(path: Path, summary: ExecutiveSummary) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Executive Summary",
        "",
        summary.summary,
        "",
        f"- Total findings: {summary.total_findings}",
        f"- Critical findings: {summary.critical_findings}",
        f"- High findings: {summary.high_findings}",
        f"- Medium findings: {summary.medium_findings}",
        f"- Low findings: {summary.low_findings}",
        "",
        "## Top Risks",
        "",
    ]
    for risk in summary.top_risks:
        lines.append(f"- {risk}")
    lines.extend(["", "## Service Breakdown", ""])
    for service, count in summary.service_breakdown.items():
        lines.append(f"- {service}: {count}")
    lines.extend(["", "## Compliance Gaps", ""])
    for gap in summary.compliance_gaps:
        lines.append(f"- {gap}")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def persist_scan_history(path: Path, findings: list[Finding], scope: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_report_payload(findings)
    payload["scope"] = scope
    payload["history_recorded_at"] = datetime.now(UTC).isoformat()
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def load_history_records(history_dir: Path) -> list[dict]:
    if not history_dir.exists():
        return []
    records = []
    for item in sorted(history_dir.glob("*.json")):
        try:
            records.append(json.loads(item.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return records


def build_trend_report(records: list[dict]) -> dict:
    if not records:
        return {
            "snapshot_count": 0,
            "latest_total_findings": 0,
            "latest_severity_breakdown": {},
            "latest_scope": "none",
            "trend_summary": "No historical scan records are available yet.",
        }
    latest = records[-1]
    return {
        "snapshot_count": len(records),
        "latest_total_findings": latest.get("finding_count", 0),
        "latest_severity_breakdown": latest.get("breakdowns", {}).get("severity", {}),
        "latest_scope": latest.get("scope", "unknown"),
        "trend_summary": (
            f"{len(records)} scan snapshot(s) are available. "
            f"The latest snapshot contains {latest.get('finding_count', 0)} findings."
        ),
    }
