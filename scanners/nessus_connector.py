from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_ONPREM_DATASET = {
    "assets": [
        {
            "asset_id": "onprem-web-01",
            "hostname": "onprem-web-01.corp.local",
            "os": "Windows Server 2016",
            "network_segment": "dmz",
            "checks": {
                "smb_signing_required": False,
                "rdp_nla_required": False,
                "host_firewall_enabled": False,
                "local_admin_password_rotation": False,
                "unsupported_os": True,
                "patch_days_overdue": 94,
            },
        },
        {
            "asset_id": "onprem-db-01",
            "hostname": "onprem-db-01.corp.local",
            "os": "Windows Server 2019",
            "network_segment": "datacenter",
            "checks": {
                "smb_signing_required": True,
                "rdp_nla_required": True,
                "host_firewall_enabled": True,
                "local_admin_password_rotation": True,
                "unsupported_os": False,
                "patch_days_overdue": 12,
            },
        },
        {
            "asset_id": "onprem-jump-01",
            "hostname": "onprem-jump-01.corp.local",
            "os": "Windows Server 2012 R2",
            "network_segment": "admin",
            "checks": {
                "smb_signing_required": False,
                "rdp_nla_required": False,
                "host_firewall_enabled": True,
                "local_admin_password_rotation": False,
                "unsupported_os": True,
                "patch_days_overdue": 47,
            },
        },
        {
            "asset_id": "onprem-ad-01",
            "hostname": "onprem-ad-01.corp.local",
            "os": "Windows Server 2012 R2",
            "network_segment": "identity",
            "checks": {
                "smb_signing_required": False,
                "rdp_nla_required": True,
                "host_firewall_enabled": False,
                "local_admin_password_rotation": False,
                "unsupported_os": True,
                "patch_days_overdue": 121,
            },
        },
        {
            "asset_id": "onprem-files-01",
            "hostname": "onprem-files-01.corp.local",
            "os": "Windows Server 2019",
            "network_segment": "datacenter",
            "checks": {
                "smb_signing_required": False,
                "rdp_nla_required": True,
                "host_firewall_enabled": True,
                "local_admin_password_rotation": True,
                "unsupported_os": False,
                "patch_days_overdue": 38,
            },
        },
        {
            "asset_id": "onprem-linux-bastion-01",
            "hostname": "onprem-linux-bastion-01.corp.local",
            "os": "Ubuntu 20.04",
            "network_segment": "admin",
            "checks": {
                "smb_signing_required": True,
                "rdp_nla_required": True,
                "host_firewall_enabled": False,
                "local_admin_password_rotation": False,
                "unsupported_os": False,
                "patch_days_overdue": 73,
            },
        },
        {
            "asset_id": "onprem-vdi-01",
            "hostname": "onprem-vdi-01.corp.local",
            "os": "Windows 10 Enterprise",
            "network_segment": "user-access",
            "checks": {
                "smb_signing_required": True,
                "rdp_nla_required": False,
                "host_firewall_enabled": False,
                "local_admin_password_rotation": True,
                "unsupported_os": False,
                "patch_days_overdue": 34,
            },
        },
        {
            "asset_id": "onprem-backup-01",
            "hostname": "onprem-backup-01.corp.local",
            "os": "Windows Server 2008 R2",
            "network_segment": "backup",
            "checks": {
                "smb_signing_required": True,
                "rdp_nla_required": True,
                "host_firewall_enabled": True,
                "local_admin_password_rotation": True,
                "unsupported_os": True,
                "patch_days_overdue": 15,
            },
        },
        {
            "asset_id": "onprem-printer-mgmt-01",
            "hostname": "onprem-printer-mgmt-01.corp.local",
            "os": "Windows Server 2016",
            "network_segment": "operations",
            "checks": {
                "smb_signing_required": False,
                "rdp_nla_required": False,
                "host_firewall_enabled": False,
                "local_admin_password_rotation": False,
                "unsupported_os": False,
                "patch_days_overdue": 140,
            },
        },
    ]
}


class NessusDatasetConnector:
    def __init__(self, dataset_path: Path | None = None):
        self.dataset_path = dataset_path

    def load_assets(self) -> list[dict[str, Any]]:
        if self.dataset_path:
            raw_payload = json.loads(self.dataset_path.read_text(encoding="utf-8"))
        else:
            raw_payload = DEFAULT_ONPREM_DATASET

        assets = raw_payload.get("assets", [])
        if not isinstance(assets, list):
            raise ValueError("Invalid Nessus dataset: 'assets' must be a list.")
        return assets
