from __future__ import annotations

from rules.cis_rules import build_finding
from scanners.base import BaseScanner
from utils.models import ScanResult


class RDSScanner(BaseScanner):
    scanner_name = "rds"

    def __init__(self, settings, client=None):
        super().__init__(settings)
        self.client = client or self.client_factory.client("rds")

    def scan(self) -> ScanResult:
        findings = []
        db_instances = self.paginated_call("describe_db_instances", "DBInstances")
        for db_instance in db_instances:
            identifier = db_instance["DBInstanceIdentifier"]
            if db_instance.get("PubliclyAccessible"):
                findings.append(
                    build_finding(
                        service="Amazon RDS",
                        resource_id=identifier,
                        issue="RDS Instance Is Publicly Accessible",
                        rule_key="rds_public_instance",
                        risk_description="Publicly accessible databases can increase the likelihood of unauthorized connection attempts.",
                    )
                )
            if not db_instance.get("StorageEncrypted"):
                findings.append(
                    build_finding(
                        service="Amazon RDS",
                        resource_id=identifier,
                        issue="RDS Storage Encryption Disabled",
                        rule_key="rds_encryption_disabled",
                        risk_description="Unencrypted database storage weakens confidentiality controls and compliance alignment.",
                    )
                )

        return ScanResult(
            scanner=self.scanner_name,
            findings=findings,
            scanned_resources=len(db_instances),
            errors=self.errors,
        )
