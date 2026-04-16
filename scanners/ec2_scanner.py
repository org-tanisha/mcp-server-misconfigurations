from __future__ import annotations

from collections.abc import Iterable

from rules.cis_rules import build_finding
from scanners.base import BaseScanner
from utils.models import ScanResult


class EC2Scanner(BaseScanner):
    scanner_name = "ec2"

    def __init__(self, settings, client=None):
        super().__init__(settings)
        self.client = client or self.client_factory.client("ec2")

    @staticmethod
    def _open_admin_ports(group_map: dict[str, dict], group_ids: list[str]) -> set[int]:
        open_ports: set[int] = set()
        for group_id in group_ids:
            group = group_map.get(group_id, {})
            for permission in group.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                for cidr in permission.get("IpRanges", []):
                    if cidr.get("CidrIp") == "0.0.0.0/0" and from_port in {22, 3389}:
                        open_ports.add(from_port)
        return open_ports

    def _volume_encryption_map(self, instances: Iterable[dict]) -> dict[str, bool]:
        volume_ids: list[str] = []
        for instance in instances:
            for mapping in instance.get("BlockDeviceMappings", []):
                ebs_data = mapping.get("Ebs", {})
                volume_id = ebs_data.get("VolumeId")
                if volume_id:
                    volume_ids.append(volume_id)

        if not volume_ids:
            return {}

        response = self.safe_call(self.client.describe_volumes, VolumeIds=sorted(set(volume_ids))) or {}
        return {
            volume["VolumeId"]: bool(volume.get("Encrypted"))
            for volume in response.get("Volumes", [])
            if volume.get("VolumeId")
        }

    def scan(self) -> ScanResult:
        findings = []
        groups_response = self.safe_call(self.client.describe_security_groups) or {}
        group_map = {
            group["GroupId"]: group
            for group in groups_response.get("SecurityGroups", [])
        }
        reservations = self.paginated_call("describe_instances", "Reservations")
        instances = []
        for reservation in reservations:
            instances.extend(reservation.get("Instances", []))
        volume_encryption_map = self._volume_encryption_map(instances)

        for instance in instances:
            instance_id = instance["InstanceId"]
            group_ids = [group["GroupId"] for group in instance.get("SecurityGroups", [])]
            metadata_options = instance.get("MetadataOptions", {})

            if metadata_options.get("HttpTokens") != "required":
                findings.append(
                    build_finding(
                        service="Amazon EC2",
                        resource_id=instance_id,
                        issue="IMDSv2 Not Enforced",
                        rule_key="ec2_imdsv2_not_required",
                        risk_description="Allowing IMDSv1 increases the risk of credential theft through SSRF and metadata abuse.",
                    )
                )

            if not instance.get("IamInstanceProfile"):
                findings.append(
                    build_finding(
                        service="Amazon EC2",
                        resource_id=instance_id,
                        issue="EC2 Instance Missing IAM Role",
                        rule_key="ec2_missing_iam_role",
                        risk_description="Workloads without a scoped IAM role often rely on static credentials and weaker secret management.",
                    )
                )

            if instance.get("State", {}).get("Name") == "stopped":
                findings.append(
                    build_finding(
                        service="Amazon EC2",
                        resource_id=instance_id,
                        issue="EC2 Instance Is Stopped",
                        rule_key="ec2_stopped_instance",
                        risk_description="Long-lived stopped instances can indicate stale assets and increase operational drift.",
                    )
                )

            for mapping in instance.get("BlockDeviceMappings", []):
                ebs_data = mapping.get("Ebs", {})
                volume_id = ebs_data.get("VolumeId")
                if not volume_id:
                    continue
                if volume_encryption_map.get(volume_id) is False:
                    findings.append(
                        build_finding(
                            service="Amazon EC2",
                            resource_id=instance_id,
                            issue="Unencrypted EBS Volume Attached",
                            rule_key="ec2_ebs_unencrypted",
                            risk_description="Unencrypted EBS volumes increase data exposure risk if snapshots or underlying storage are accessed improperly.",
                            metadata={"volume_id": volume_id},
                        )
                    )

            if instance.get("PublicIpAddress"):
                findings.append(
                    build_finding(
                        service="Amazon EC2",
                        resource_id=instance_id,
                        issue="EC2 Instance Has Public IP",
                        rule_key="ec2_public_ip",
                        risk_description="Direct internet exposure increases attack surface for compute workloads.",
                        metadata={"security_groups": ",".join(group_ids)},
                    )
                )
                open_ports = self._open_admin_ports(group_map, group_ids)
                if 22 in open_ports:
                    findings.append(
                        build_finding(
                            service="Amazon EC2",
                            resource_id=instance_id,
                            issue="Public EC2 Instance Exposes SSH",
                            rule_key="ec2_public_ssh",
                            risk_description="A public IP combined with open SSH creates a high-probability remote attack path.",
                            metadata={"security_groups": ",".join(group_ids)},
                        )
                    )
                if 3389 in open_ports:
                    findings.append(
                        build_finding(
                            service="Amazon EC2",
                            resource_id=instance_id,
                            issue="Public EC2 Instance Exposes RDP",
                            rule_key="ec2_public_rdp",
                            risk_description="A public IP combined with open RDP creates a high-probability remote attack path.",
                            metadata={"security_groups": ",".join(group_ids)},
                        )
                    )

        return ScanResult(
            scanner=self.scanner_name,
            findings=findings,
            scanned_resources=len(instances),
            errors=self.errors,
        )
