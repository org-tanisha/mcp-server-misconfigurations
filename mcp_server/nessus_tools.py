from __future__ import annotations

from pathlib import Path

from mcp_server.config import Settings
from scanners.nessus_scanner import NessusOnPremScanner
from utils.reporting import write_json_report, write_markdown_report


class NessusToolRegistry:
    def __init__(self, settings: Settings):
        self.settings = settings

    def scan_onprem_infrastructure_nessus(self) -> list[dict]:
        return [item.model_dump() for item in NessusOnPremScanner(self.settings).scan().findings]

    def generate_onprem_nessus_report(self) -> dict:
        findings = NessusOnPremScanner(self.settings).scan().findings
        output_dir = Path(self.settings.output_dir)
        if not output_dir.is_absolute():
            repo_root = Path(__file__).resolve().parents[1]
            output_dir = (repo_root / output_dir).resolve()
        json_path = write_json_report(output_dir / "onprem_nessus_report.json", findings)
        markdown_path = write_markdown_report(output_dir / "onprem_nessus_report.md", findings)
        return {
            "json_report": str(json_path),
            "markdown_report": str(markdown_path),
            "finding_count": len(findings),
        }
