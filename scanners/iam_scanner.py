from __future__ import annotations

import json
from typing import Any

from rules.cis_rules import build_finding
from scanners.base import BaseScanner
from utils.models import ScanResult


class IAMScanner(BaseScanner):
    scanner_name = "iam"

    def __init__(self, settings, client=None):
        super().__init__(settings)
        self.client = client or self.client_factory.client("iam")

    @staticmethod
    def _normalize_statements(document: dict[str, Any]) -> list[dict[str, Any]]:
        statements = document.get("Statement", [])
        if isinstance(statements, dict):
            return [statements]
        return statements

    @staticmethod
    def _as_list(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(item) for item in value]
        return []

    def _document_is_overly_permissive(self, document: dict[str, Any]) -> bool:
        for statement in self._normalize_statements(document):
            if statement.get("Effect") != "Allow":
                continue
            actions = self._as_list(statement.get("Action"))
            not_actions = self._as_list(statement.get("NotAction"))
            resources = self._as_list(statement.get("Resource"))
            if (
                "*" in actions
                or any(action.endswith(":*") for action in actions)
                or "*" in resources
                or bool(not_actions)
            ):
                return True
        return False

    def _policy_document(self, policy_arn: str, version_id: str) -> dict[str, Any]:
        version = self.safe_call(
            self.client.get_policy_version,
            PolicyArn=policy_arn,
            VersionId=version_id,
        )
        if not version:
            return {}
        document = version["PolicyVersion"]["Document"]
        if isinstance(document, str):
            document = json.loads(document)
        return document

    def _add_policy_finding(self, findings: list, resource_id: str, policy_name: str, principal_type: str) -> None:
        findings.append(
            build_finding(
                service="IAM",
                resource_id=resource_id,
                issue="Overly Permissive IAM Policy",
                rule_key="iam_wildcard_policy",
                risk_description="Wildcard permissions, broad resources, or NotAction logic can grant excessive access and enable privilege escalation.",
                metadata={"policy_name": policy_name, "principal_type": principal_type},
            )
        )

    def scan(self) -> ScanResult:
        findings = []
        policies = self.paginated_call("list_policies", "Policies", Scope="Local")
        for policy in policies:
            document = self._policy_document(policy["Arn"], policy["DefaultVersionId"])
            if document and self._document_is_overly_permissive(document):
                self._add_policy_finding(findings, policy["Arn"], policy["PolicyName"], "customer-managed-policy")

        users = self.paginated_call("list_users", "Users")
        for user in users:
            devices_response = self.safe_call(self.client.list_mfa_devices, UserName=user["UserName"]) or {}
            devices = devices_response.get("MFADevices", [])
            if not devices:
                findings.append(
                    build_finding(
                        service="IAM",
                        resource_id=user["UserName"],
                        issue="IAM User Without MFA",
                        rule_key="iam_user_without_mfa",
                        risk_description="Interactive IAM users without MFA are at increased risk of account compromise.",
                    )
                )
            attached_policies = self.paginated_call(
                "list_attached_user_policies",
                "AttachedPolicies",
                UserName=user["UserName"],
            )
            for attached in attached_policies:
                policy = self.safe_call(self.client.get_policy, PolicyArn=attached["PolicyArn"])
                if not policy:
                    continue
                document = self._policy_document(
                    attached["PolicyArn"],
                    policy["Policy"]["DefaultVersionId"],
                )
                if document and self._document_is_overly_permissive(document):
                    self._add_policy_finding(findings, user["UserName"], attached["PolicyName"], "iam-user")

        roles = self.paginated_call("list_roles", "Roles")
        for role in roles:
            attached_policies = self.paginated_call(
                "list_attached_role_policies",
                "AttachedPolicies",
                RoleName=role["RoleName"],
            )
            for attached in attached_policies:
                policy = self.safe_call(self.client.get_policy, PolicyArn=attached["PolicyArn"])
                if not policy:
                    continue
                document = self._policy_document(
                    attached["PolicyArn"],
                    policy["Policy"]["DefaultVersionId"],
                )
                if document and self._document_is_overly_permissive(document):
                    self._add_policy_finding(findings, role["Arn"], attached["PolicyName"], "iam-role")

        return ScanResult(
            scanner=self.scanner_name,
            findings=findings,
            scanned_resources=len(policies) + len(users) + len(roles),
            errors=self.errors,
        )
