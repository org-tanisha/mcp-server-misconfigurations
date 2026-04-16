from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import BotoCoreError
from botocore.exceptions import ClientError

from rules.cis_rules import build_finding
from scanners.base import BaseScanner
from utils.models import ScanResult


class S3Scanner(BaseScanner):
    scanner_name = "s3"

    def __init__(self, settings, client=None):
        super().__init__(settings)
        self.client = client or self.client_factory.client("s3")

    @staticmethod
    def _as_list(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        if value is None:
            return []
        return [value]

    def _s3_call(
        self,
        method_name: str,
        *,
        expected_missing_codes: set[str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        method = getattr(self.client, method_name)
        try:
            return method(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if expected_missing_codes and code in expected_missing_codes:
                return None
            self.errors.append(f"{self.scanner_name}:{method_name}:{exc}")
            return None
        except BotoCoreError as exc:
            self.errors.append(f"{self.scanner_name}:{method_name}:{exc}")
            return None

    def _policy_enforces_tls(self, policy_document: dict[str, Any]) -> bool:
        for statement in self._as_list(policy_document.get("Statement")):
            if not isinstance(statement, dict):
                continue
            if statement.get("Effect") != "Deny":
                continue
            condition = statement.get("Condition", {})
            if not isinstance(condition, dict):
                continue
            bool_condition = condition.get("Bool", {})
            if not isinstance(bool_condition, dict):
                continue
            secure_transport = bool_condition.get("aws:SecureTransport")
            if secure_transport in {"false", False}:
                return True
        return False

    def _bucket_acl_is_public(self, acl: dict[str, Any]) -> bool:
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("Type") != "Group":
                continue
            uri = grantee.get("URI", "")
            if uri in {
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            }:
                return True
        return False

    def _missing_required_tags(self, tag_set: list[dict[str, str]]) -> list[str]:
        required_tags = {"owner", "data_classification"}
        present = {str(tag.get("Key", "")).lower() for tag in tag_set}
        return sorted(required_tags - present)

    def scan(self) -> ScanResult:
        findings = []
        response = self.safe_call(self.client.list_buckets) or {}
        buckets = response.get("Buckets", [])
        for bucket in buckets:
            bucket_name = bucket["Name"]
            public_access = self._s3_call(
                "get_public_access_block",
                Bucket=bucket_name,
                expected_missing_codes={"NoSuchPublicAccessBlockConfiguration"},
            )
            config = (public_access or {}).get("PublicAccessBlockConfiguration", {})
            if not public_access or not all(config.values()):
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Publicly Accessible Bucket",
                        rule_key="s3_public_bucket",
                        risk_description="Missing Block Public Access settings increase the risk of unintended exposure.",
                    )
                )

            policy_status = self._s3_call(
                "get_bucket_policy_status",
                Bucket=bucket_name,
                expected_missing_codes={"NoSuchBucketPolicy"},
            )
            if (policy_status or {}).get("PolicyStatus", {}).get("IsPublic"):
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Bucket Policy Allows Public Access",
                        rule_key="s3_public_policy",
                        risk_description="Public bucket policies can expose objects and metadata directly to unauthenticated users.",
                    )
                )

            acl = self._s3_call("get_bucket_acl", Bucket=bucket_name)
            if acl and self._bucket_acl_is_public(acl):
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Bucket ACL Grants Public Access",
                        rule_key="s3_public_acl",
                        risk_description="Legacy ACL grants to global groups can unintentionally expose sensitive data.",
                    )
                )

            ownership_controls = self._s3_call(
                "get_bucket_ownership_controls",
                Bucket=bucket_name,
                expected_missing_codes={"OwnershipControlsNotFoundError", "NoSuchOwnershipControls"},
            )
            ownership_rules = (ownership_controls or {}).get("OwnershipControls", {}).get("Rules", [])
            ownership_mode = ownership_rules[0].get("ObjectOwnership") if ownership_rules else None
            if ownership_mode != "BucketOwnerEnforced":
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Object ACLs Still Enabled",
                        rule_key="s3_object_acl_enabled",
                        risk_description="Keeping object ACLs enabled allows per-object permissions that can bypass centralized bucket controls.",
                    )
                )

            encryption = self._s3_call(
                "get_bucket_encryption",
                Bucket=bucket_name,
                expected_missing_codes={"ServerSideEncryptionConfigurationNotFoundError"},
            )
            encryption_rules = (encryption or {}).get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not encryption_rules:
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Default Encryption Disabled",
                        rule_key="s3_encryption_disabled",
                        risk_description="Unencrypted storage increases risk of data disclosure and weakens compliance posture.",
                    )
                )
            else:
                default_encryption = encryption_rules[0].get("ApplyServerSideEncryptionByDefault", {})
                if default_encryption.get("SSEAlgorithm") != "aws:kms":
                    findings.append(
                        build_finding(
                            service="Amazon S3",
                            resource_id=bucket_name,
                            issue="Default Encryption Does Not Enforce KMS",
                            rule_key="s3_kms_not_enforced",
                            risk_description="Using SSE-S3 instead of KMS can reduce key governance and encryption audit controls for sensitive data.",
                        )
                    )

            policy = self._s3_call(
                "get_bucket_policy",
                Bucket=bucket_name,
                expected_missing_codes={"NoSuchBucketPolicy"},
            )
            policy_document = {}
            if policy:
                raw_policy = policy.get("Policy")
                if isinstance(raw_policy, str):
                    policy_document = json.loads(raw_policy)
            if not policy_document or not self._policy_enforces_tls(policy_document):
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Bucket Policy Does Not Enforce TLS",
                        rule_key="s3_tls_not_enforced",
                        risk_description="Allowing non-TLS requests can expose data in transit to interception and tampering risks.",
                    )
                )

            versioning = self.safe_call(self.client.get_bucket_versioning, Bucket=bucket_name) or {}
            if versioning.get("Status") != "Enabled":
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Bucket Versioning Disabled",
                        rule_key="s3_versioning_disabled",
                        risk_description="Without versioning, recovery from accidental deletion or overwrite is weaker.",
                    )
                )
            elif versioning.get("MFADelete") != "Enabled":
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="MFA Delete Disabled on Versioned Bucket",
                        rule_key="s3_mfa_delete_disabled",
                        risk_description="Without MFA Delete, versioned objects can be removed or altered more easily by compromised credentials.",
                    )
                )

            logging = self._s3_call("get_bucket_logging", Bucket=bucket_name) or {}
            if not logging.get("LoggingEnabled"):
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Server Access Logging Disabled",
                        rule_key="s3_access_logging_disabled",
                        risk_description="Missing access logs reduces visibility into object access patterns and incident investigations.",
                    )
                )

            lifecycle = self._s3_call(
                "get_bucket_lifecycle_configuration",
                Bucket=bucket_name,
                expected_missing_codes={"NoSuchLifecycleConfiguration"},
            )
            if not lifecycle or not lifecycle.get("Rules"):
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Lifecycle Policy Missing",
                        rule_key="s3_lifecycle_missing",
                        risk_description="Without lifecycle controls, stale or noncurrent objects can accumulate and increase cost and retention risk.",
                    )
                )

            replication = self._s3_call(
                "get_bucket_replication",
                Bucket=bucket_name,
                expected_missing_codes={"ReplicationConfigurationNotFoundError", "NoSuchReplicationConfiguration"},
            )
            replication_rules = (replication or {}).get("ReplicationConfiguration", {}).get("Rules", [])
            if not replication_rules:
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Replication Not Configured",
                        rule_key="s3_replication_disabled",
                        risk_description="Buckets without replication have weaker resilience for regional outages and accidental loss events.",
                    )
                )

            tagging = self._s3_call(
                "get_bucket_tagging",
                Bucket=bucket_name,
                expected_missing_codes={"NoSuchTagSet"},
            )
            missing_tags = self._missing_required_tags((tagging or {}).get("TagSet", []))
            if missing_tags:
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Required Bucket Classification Tags Missing",
                        rule_key="s3_required_tags_missing",
                        risk_description="Missing ownership and classification tags weakens accountability and data governance controls.",
                        metadata={"missing_tags": ",".join(missing_tags)},
                    )
                )

            object_lock = self._s3_call(
                "get_object_lock_configuration",
                Bucket=bucket_name,
                expected_missing_codes={"ObjectLockConfigurationNotFoundError"},
            )
            if (object_lock or {}).get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
                findings.append(
                    build_finding(
                        service="Amazon S3",
                        resource_id=bucket_name,
                        issue="Object Lock Not Enabled",
                        rule_key="s3_object_lock_disabled",
                        risk_description="Buckets without Object Lock cannot enforce immutability controls for regulated or ransomware-sensitive data.",
                    )
                )

        return ScanResult(
            scanner=self.scanner_name,
            findings=findings,
            scanned_resources=len(buckets),
            errors=self.errors,
        )
