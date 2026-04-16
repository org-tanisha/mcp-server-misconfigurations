from __future__ import annotations

from rules.cis_rules import build_finding
from scanners.base import BaseScanner
from utils.models import ScanResult


class CloudTrailScanner(BaseScanner):
    scanner_name = "cloudtrail"

    def __init__(self, settings, client=None):
        super().__init__(settings)
        self.client = client or self.client_factory.client("cloudtrail")

    def scan(self) -> ScanResult:
        findings = []
        response = self.safe_call(self.client.describe_trails, includeShadowTrails=False) or {}
        trails = response.get("trailList", [])
        if not trails:
            findings.append(
                build_finding(
                    service="AWS CloudTrail",
                    resource_id="account",
                    issue="CloudTrail Logging Disabled",
                    rule_key="cloudtrail_disabled",
                    risk_description="Missing CloudTrail visibility reduces the ability to detect and investigate suspicious activity.",
                )
            )
            return ScanResult(scanner=self.scanner_name, findings=findings, scanned_resources=0, errors=self.errors)

        for trail in trails:
            status = self.safe_call(self.client.get_trail_status, Name=trail["TrailARN"]) or {}
            if not status.get("IsLogging") or not trail.get("IsMultiRegionTrail"):
                findings.append(
                    build_finding(
                        service="AWS CloudTrail",
                        resource_id=trail["Name"],
                        issue="CloudTrail Misconfigured",
                        rule_key="cloudtrail_disabled",
                        risk_description="Logging gaps or single-region coverage can leave key activity unmonitored.",
                    )
                )

        return ScanResult(
            scanner=self.scanner_name,
            findings=findings,
            scanned_resources=len(trails),
            errors=self.errors,
        )
