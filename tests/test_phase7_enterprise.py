from __future__ import annotations

import json
from pathlib import Path

from mcp_server.config import Settings
from mcp_server.tools import ToolRegistry
from rules.cis_rules import build_finding
from utils.reporting import build_trend_report, load_history_records, persist_scan_history


def sample_findings(profile: str):
    finding = build_finding(
        service="AWS CloudTrail",
        resource_id="account",
        issue="CloudTrail Logging Disabled",
        rule_key="cloudtrail_disabled",
        risk_description="Logging gaps reduce detection capability.",
        metadata={"aws_profile": profile},
    )
    return [finding]


def test_persist_and_load_history(tmp_path: Path):
    history_file = tmp_path / "history" / "snapshot.json"
    persist_scan_history(history_file, sample_findings("default"), scope="default")
    records = load_history_records(tmp_path / "history")
    assert len(records) == 1
    assert records[0]["finding_count"] == 1


def test_build_trend_report_summarizes_latest_snapshot():
    records = [
        {"finding_count": 2, "scope": "default", "breakdowns": {"severity": {"Critical": 1}}},
        {"finding_count": 1, "scope": "multi-account", "breakdowns": {"severity": {"Medium": 1}}},
    ]
    report = build_trend_report(records)
    assert report["snapshot_count"] == 2
    assert report["latest_total_findings"] == 1
    assert report["latest_scope"] == "multi-account"


class EnterpriseStubRegistry(ToolRegistry):
    def _scan_all_findings(self, settings=None):
        active = settings or self.settings
        profile = active.aws_profile or "default"
        return sample_findings(profile)


def test_scan_multiple_accounts_aggregates_profiles(tmp_path: Path):
    settings = Settings(
        aws_profile="default",
        aws_profiles=["default", "sandbox"],
        output_dir=tmp_path,
        history_dir=tmp_path / "history",
    )
    registry = EnterpriseStubRegistry(settings)
    result = registry.scan_multiple_accounts()
    assert result["account_count"] == 2
    assert result["finding_count"] == 2
    assert Path(result["history_record"]).exists()
