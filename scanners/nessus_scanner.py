from __future__ import annotations

import json
from pathlib import Path

from rules.cis_rules import build_finding
from scanners.base import BaseScanner
from scanners.nessus_connector import NessusDatasetConnector
from utils.models import ScanResult


class NessusOnPremScanner(BaseScanner):
    scanner_name = "nessus_onprem"

    def __init__(self, settings, connector: NessusDatasetConnector | None = None):
        super().__init__(settings)
        dataset_path = Path(settings.onprem_dataset_path) if settings.onprem_dataset_path else None
        if dataset_path and not dataset_path.is_absolute():
            repo_root = Path(__file__).resolve().parents[1]
            dataset_path = (repo_root / dataset_path).resolve()
        self.connector = connector or NessusDatasetConnector(dataset_path=dataset_path)

    def scan(self) -> ScanResult:
        findings = []
        try:
            assets = self.connector.load_assets()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            self.errors.append(f"{self.scanner_name}:load_assets:{exc}")
            return ScanResult(scanner=self.scanner_name, findings=findings, scanned_resources=0, errors=self.errors)

        for asset in assets:
            asset_id = str(asset.get("asset_id", "unknown-asset"))
            hostname = str(asset.get("hostname", "unknown-host"))
            checks = asset.get("checks", {}) if isinstance(asset.get("checks"), dict) else {}
            metadata = {
                "hostname": hostname,
                "network_segment": str(asset.get("network_segment", "unknown")),
                "os": str(asset.get("os", "unknown")),
                "data_source": "nessus-connector",
            }

            if checks.get("smb_signing_required") is False:
                findings.append(
                    build_finding(
                        service="On-Prem Infrastructure (Nessus)",
                        resource_id=asset_id,
                        issue="SMB Signing Not Enforced",
                        rule_key="onprem_smb_signing_disabled",
                        risk_description="SMB relay attacks become more feasible when SMB signing is disabled.",
                        metadata=metadata,
                    )
                )

            if checks.get("rdp_nla_required") is False:
                findings.append(
                    build_finding(
                        service="On-Prem Infrastructure (Nessus)",
                        resource_id=asset_id,
                        issue="RDP Network Level Authentication Disabled",
                        rule_key="onprem_rdp_nla_disabled",
                        risk_description="RDP endpoints without NLA are more susceptible to credential theft and brute-force attacks.",
                        metadata=metadata,
                    )
                )

            if checks.get("host_firewall_enabled") is False:
                findings.append(
                    build_finding(
                        service="On-Prem Infrastructure (Nessus)",
                        resource_id=asset_id,
                        issue="Host Firewall Disabled",
                        rule_key="onprem_host_firewall_disabled",
                        risk_description="Disabling host firewall protections exposes services broadly and weakens segmentation controls.",
                        metadata=metadata,
                    )
                )

            if checks.get("local_admin_password_rotation") is False:
                findings.append(
                    build_finding(
                        service="On-Prem Infrastructure (Nessus)",
                        resource_id=asset_id,
                        issue="Local Admin Password Rotation Missing",
                        rule_key="onprem_admin_password_rotation_missing",
                        risk_description="Static local admin credentials can be reused laterally after compromise.",
                        metadata=metadata,
                    )
                )

            if checks.get("unsupported_os") is True:
                findings.append(
                    build_finding(
                        service="On-Prem Infrastructure (Nessus)",
                        resource_id=asset_id,
                        issue="Unsupported Operating System Detected",
                        rule_key="onprem_unsupported_os",
                        risk_description="Unsupported operating systems no longer receive security patches and carry elevated exploit risk.",
                        metadata=metadata,
                    )
                )

            patch_days_overdue = checks.get("patch_days_overdue")
            if isinstance(patch_days_overdue, int) and patch_days_overdue > 30:
                findings.append(
                    build_finding(
                        service="On-Prem Infrastructure (Nessus)",
                        resource_id=asset_id,
                        issue="Critical Patches Overdue",
                        rule_key="onprem_patching_overdue",
                        risk_description="Delayed patching increases exposure windows for known exploited vulnerabilities.",
                        metadata={**metadata, "patch_days_overdue": patch_days_overdue},
                    )
                )

        return ScanResult(
            scanner=self.scanner_name,
            findings=findings,
            scanned_resources=len(assets),
            errors=self.errors,
        )
