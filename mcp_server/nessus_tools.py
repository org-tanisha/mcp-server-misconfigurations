from __future__ import annotations

import logging
from pathlib import Path
from collections import Counter

from mcp_server.config import Settings
from scanners.nessus_scanner import NessusOnPremScanner
from utils.reporting import write_json_report, write_markdown_report
from utils.redaction import default_redactor
from utils.models import Finding


class NessusToolRegistry:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.logger = logging.getLogger("mcp_server.nessus_tools")

    def _redact_findings(self, findings: list[Finding]) -> list[dict]:
        """Redact and dump findings."""
        redacted = []
        for finding in findings:
            data = finding.model_dump()
            redacted.append(default_redactor.redact_dict(data))
        return redacted

    def scan_onprem_infrastructure_nessus(self) -> list[dict]:
        self.logger.info("Starting Nessus on-prem scan")
        try:
            findings = NessusOnPremScanner(self.settings).scan().findings
            self.logger.info(f"Nessus scan found {len(findings)} issues")
            
            # Log summary
            severity_counts = Counter(f.severity.upper() for f in findings)
            for severity, count in severity_counts.items():
                self.logger.info(f"  {severity}: {count}")
                
            return self._redact_findings(findings)
        except Exception as e:
            self.logger.error(f"Nessus scan failed: {e}")
            return []

    def generate_onprem_nessus_report(self) -> dict:
        self.logger.info("Generating Nessus on-prem report")
        findings = NessusOnPremScanner(self.settings).scan().findings
        output_dir = Path(self.settings.output_dir)
        if not output_dir.is_absolute():
            repo_root = Path(__file__).resolve().parents[1]
            output_dir = (repo_root / output_dir).resolve()
        
        json_path = write_json_report(output_dir / "onprem_nessus_report.json", findings)
        markdown_path = write_markdown_report(output_dir / "onprem_nessus_report.md", findings)
        
        self.logger.info(f"Report generated: {json_path}")
        return {
            "json_report": str(json_path),
            "markdown_report": str(markdown_path),
            "finding_count": len(findings),
        }
