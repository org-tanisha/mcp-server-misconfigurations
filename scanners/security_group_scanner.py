from __future__ import annotations

from rules.cis_rules import build_finding
from scanners.base import BaseScanner
from utils.models import ScanResult


class SecurityGroupScanner(BaseScanner):
    scanner_name = "security-groups"

    def __init__(self, settings, client=None):
        super().__init__(settings)
        self.client = client or self.client_factory.client("ec2")

    def scan(self) -> ScanResult:
        findings = []
        groups = self.paginated_call("describe_security_groups", "SecurityGroups")
        for group in groups:
            for permission in group.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                ranges = permission.get("IpRanges", [])
                for cidr in ranges:
                    if cidr.get("CidrIp") != "0.0.0.0/0":
                        continue
                    if from_port == 22:
                        findings.append(
                            build_finding(
                                service="Security Group",
                                resource_id=group["GroupId"],
                                issue="SSH Open to the Internet",
                                rule_key="security_group_open_ssh",
                                risk_description="Unrestricted SSH access creates a direct remote administration attack path.",
                            )
                        )
                    if from_port == 3389:
                        findings.append(
                            build_finding(
                                service="Security Group",
                                resource_id=group["GroupId"],
                                issue="RDP Open to the Internet",
                                rule_key="security_group_open_rdp",
                                risk_description="Unrestricted RDP access creates a direct remote administration attack path.",
                            )
                        )

        return ScanResult(
            scanner=self.scanner_name,
            findings=findings,
            scanned_resources=len(groups),
            errors=self.errors,
        )
