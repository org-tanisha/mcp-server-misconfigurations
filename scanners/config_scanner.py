from __future__ import annotations

from rules.cis_rules import build_finding
from scanners.base import BaseScanner
from utils.models import ScanResult


class AWSConfigScanner(BaseScanner):
    scanner_name = "aws-config"

    def __init__(self, settings, client=None):
        super().__init__(settings)
        self.client = client or self.client_factory.client("config")

    def scan(self) -> ScanResult:
        findings = []
        recorders_response = self.safe_call(self.client.describe_configuration_recorders) or {}
        delivery_response = self.safe_call(self.client.describe_delivery_channels) or {}
        status_response = self.safe_call(self.client.describe_configuration_recorder_status) or {}

        recorders = recorders_response.get("ConfigurationRecorders", [])
        delivery_channels = delivery_response.get("DeliveryChannels", [])
        statuses = status_response.get("ConfigurationRecordersStatus", [])

        if not recorders or not delivery_channels:
            findings.append(
                build_finding(
                    service="AWS Config",
                    resource_id="account",
                    issue="AWS Config Recording Disabled",
                    rule_key="aws_config_disabled",
                    risk_description="Without AWS Config, configuration drift and compliance evidence collection are weaker.",
                )
            )
        else:
            for status in statuses:
                if not status.get("recording"):
                    findings.append(
                        build_finding(
                            service="AWS Config",
                            resource_id=status.get("name", "configuration-recorder"),
                            issue="AWS Config Recorder Not Recording",
                            rule_key="aws_config_disabled",
                            risk_description="A stopped configuration recorder weakens change visibility and compliance monitoring.",
                        )
                    )

        return ScanResult(
            scanner=self.scanner_name,
            findings=findings,
            scanned_resources=len(recorders),
            errors=self.errors,
        )

