from __future__ import annotations

import json
from pathlib import Path

from mcp_server.config import Settings
from mcp_server.nessus_tools import NessusToolRegistry


def test_registry_exposes_nessus_onprem_findings():
    settings = Settings(use_mocks=True)
    registry = NessusToolRegistry(settings)
    findings = registry.scan_onprem_infrastructure_nessus()
    assert len(findings) >= 1
    assert findings[0]["service"] == "On-Prem Infrastructure (Nessus)"


def test_registry_reads_custom_nessus_dataset(tmp_path: Path):
    dataset = tmp_path / "custom_nessus.json"
    dataset.write_text(
        json.dumps(
            {
                "assets": [
                    {
                        "asset_id": "custom-onprem-1",
                        "hostname": "custom-onprem-1.corp.local",
                        "os": "Windows Server 2019",
                        "network_segment": "dmz",
                        "checks": {
                            "smb_signing_required": False,
                            "rdp_nla_required": True,
                            "host_firewall_enabled": True,
                            "local_admin_password_rotation": True,
                            "unsupported_os": False,
                            "patch_days_overdue": 5,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    settings = Settings(use_mocks=True, onprem_dataset_path=dataset)
    registry = NessusToolRegistry(settings)
    findings = registry.scan_onprem_infrastructure_nessus()
    assert len(findings) == 1
    assert findings[0]["resource_id"] == "custom-onprem-1"


def test_registry_resolves_relative_dataset_path_from_repo(monkeypatch, tmp_path: Path):
    monkeypatch.chdir(tmp_path)
    settings = Settings(use_mocks=True, onprem_dataset_path=Path("scanners\\data\\onprem_nessus_dataset.json"))
    registry = NessusToolRegistry(settings)
    findings = registry.scan_onprem_infrastructure_nessus()
    assert len(findings) >= 1
