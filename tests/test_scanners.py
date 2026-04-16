from __future__ import annotations

from botocore.exceptions import ClientError

from mcp_server.config import Settings
from scanners.config_scanner import AWSConfigScanner
from scanners.ec2_scanner import EC2Scanner
from scanners.cloudtrail_scanner import CloudTrailScanner
from scanners.iam_scanner import IAMScanner
from scanners.nessus_scanner import NessusOnPremScanner
from scanners.rds_scanner import RDSScanner
from scanners.s3_scanner import S3Scanner
from scanners.security_group_scanner import SecurityGroupScanner


class MockS3Client:
    @staticmethod
    def _client_error(code: str, operation: str) -> ClientError:
        return ClientError({"Error": {"Code": code, "Message": code}}, operation)

    def list_buckets(self):
        return {"Buckets": [{"Name": "example-bucket"}]}

    def get_public_access_block(self, Bucket):
        raise self._client_error("NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock")

    def get_bucket_encryption(self, Bucket):
        raise self._client_error("ServerSideEncryptionConfigurationNotFoundError", "GetBucketEncryption")

    def get_bucket_policy_status(self, Bucket):
        return {"PolicyStatus": {"IsPublic": True}}

    def get_bucket_acl(self, Bucket):
        return {
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    }
                }
            ]
        }

    def get_bucket_ownership_controls(self, Bucket):
        return {"OwnershipControls": {"Rules": [{"ObjectOwnership": "ObjectWriter"}]}}

    def get_bucket_policy(self, Bucket):
        raise self._client_error("NoSuchBucketPolicy", "GetBucketPolicy")

    def get_bucket_versioning(self, Bucket):
        return {}

    def get_bucket_logging(self, Bucket):
        return {}

    def get_bucket_lifecycle_configuration(self, Bucket):
        raise self._client_error("NoSuchLifecycleConfiguration", "GetBucketLifecycleConfiguration")

    def get_bucket_replication(self, Bucket):
        raise self._client_error("ReplicationConfigurationNotFoundError", "GetBucketReplication")

    def get_bucket_tagging(self, Bucket):
        raise self._client_error("NoSuchTagSet", "GetBucketTagging")

    def get_object_lock_configuration(self, Bucket):
        raise self._client_error("ObjectLockConfigurationNotFoundError", "GetObjectLockConfiguration")


class MockIAMPaginator:
    def __init__(self, key, values):
        self.key = key
        self.values = values

    def paginate(self, **kwargs):
        return [{self.key: self.values}]


class MockIAMClient:
    def list_policies(self, Scope):
        return {
            "Policies": [
                {
                    "Arn": "arn:aws:iam::123456789012:policy/AdminLike",
                    "DefaultVersionId": "v1",
                    "PolicyName": "AdminLike",
                }
            ]
        }

    def get_policy_version(self, PolicyArn, VersionId):
        return {
            "PolicyVersion": {
                "Document": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                }
            }
        }

    def get_paginator(self, name):
        mapping = {
            "list_policies": MockIAMPaginator(
                "Policies",
                [
                    {
                        "Arn": "arn:aws:iam::123456789012:policy/AdminLike",
                        "DefaultVersionId": "v1",
                        "PolicyName": "AdminLike",
                    }
                ],
            ),
            "list_users": MockIAMPaginator("Users", [{"UserName": "alice"}]),
            "list_attached_user_policies": MockIAMPaginator(
                "AttachedPolicies",
                [{"PolicyArn": "arn:aws:iam::123456789012:policy/UserPower", "PolicyName": "UserPower"}],
            ),
            "list_roles": MockIAMPaginator(
                "Roles",
                [{"RoleName": "app-role", "Arn": "arn:aws:iam::123456789012:role/app-role"}],
            ),
            "list_attached_role_policies": MockIAMPaginator(
                "AttachedPolicies",
                [{"PolicyArn": "arn:aws:iam::123456789012:policy/RoleAdmin", "PolicyName": "RoleAdmin"}],
            ),
        }
        return mapping[name]

    def list_mfa_devices(self, UserName):
        return {"MFADevices": []}

    def get_policy(self, PolicyArn):
        return {"Policy": {"DefaultVersionId": "v1"}}


class MockEC2Client:
    def get_paginator(self, name):
        if name == "describe_security_groups":
            return MockIAMPaginator(
                "SecurityGroups",
                [
                    {
                        "GroupId": "sg-1234",
                        "IpPermissions": [
                            {"FromPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                            {"FromPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                        ],
                    }
                ],
            )
        if name == "describe_instances":
            return MockIAMPaginator(
                "Reservations",
                [
                    {
                        "Instances": [
                            {
                                "InstanceId": "i-1234",
                                "PublicIpAddress": "1.2.3.4",
                                "SecurityGroups": [{"GroupId": "sg-1234"}],
                                "MetadataOptions": {"HttpTokens": "optional"},
                                "State": {"Name": "running"},
                                "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-aaaa"}}],
                            },
                            {
                                "InstanceId": "i-5678",
                                "SecurityGroups": [{"GroupId": "sg-1234"}],
                                "MetadataOptions": {"HttpTokens": "required"},
                                "IamInstanceProfile": {"Arn": "arn:aws:iam::123456789012:instance-profile/app"},
                                "State": {"Name": "stopped"},
                                "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-bbbb"}}],
                            }
                        ]
                    }
                ],
            )
        raise KeyError(name)

    def describe_security_groups(self):
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-1234",
                    "IpPermissions": [
                        {"FromPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                        {"FromPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    ],
                }
            ]
        }

    def describe_volumes(self, VolumeIds):
        volumes = {
            "vol-aaaa": {"VolumeId": "vol-aaaa", "Encrypted": False},
            "vol-bbbb": {"VolumeId": "vol-bbbb", "Encrypted": True},
        }
        return {"Volumes": [volumes[volume_id] for volume_id in VolumeIds if volume_id in volumes]}


class MockRDSClient:
    def get_paginator(self, name):
        if name == "describe_db_instances":
            return MockIAMPaginator(
                "DBInstances",
                [
                    {
                        "DBInstanceIdentifier": "db-1",
                        "PubliclyAccessible": True,
                        "StorageEncrypted": False,
                    }
                ],
            )
        raise KeyError(name)

    def describe_db_instances(self):
        return {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "db-1",
                    "PubliclyAccessible": True,
                    "StorageEncrypted": False,
                }
            ]
        }


class MockCloudTrailClient:
    def describe_trails(self, includeShadowTrails=False):
        return {"trailList": []}


class MockConfigClient:
    def describe_configuration_recorders(self):
        return {"ConfigurationRecorders": []}

    def describe_delivery_channels(self):
        return {"DeliveryChannels": []}

    def describe_configuration_recorder_status(self):
        return {"ConfigurationRecordersStatus": []}


class MockNessusConnector:
    def load_assets(self):
        return [
            {
                "asset_id": "onprem-node-1",
                "hostname": "onprem-node-1.corp.local",
                "os": "Windows Server 2012 R2",
                "network_segment": "dmz",
                "checks": {
                    "smb_signing_required": False,
                    "rdp_nla_required": False,
                    "host_firewall_enabled": False,
                    "local_admin_password_rotation": False,
                    "unsupported_os": True,
                    "patch_days_overdue": 65,
                },
            }
        ]


def test_s3_scanner_detects_bucket_misconfiguration_findings():
    settings = Settings(use_mocks=True)
    scanner = S3Scanner(settings, client=MockS3Client())
    result = scanner.scan()
    assert result.scanned_resources == 1
    assert len(result.findings) == 12


def test_s3_scanner_detects_three_findings():
    test_s3_scanner_detects_bucket_misconfiguration_findings()


def test_iam_scanner_detects_policy_and_mfa_gaps():
    settings = Settings(use_mocks=True)
    scanner = IAMScanner(settings, client=MockIAMClient())
    result = scanner.scan()
    assert len(result.findings) == 4
    assert {finding.issue for finding in result.findings} == {
        "Overly Permissive IAM Policy",
        "IAM User Without MFA",
    }


def test_security_group_scanner_detects_open_admin_ports():
    settings = Settings(use_mocks=True)
    scanner = SecurityGroupScanner(settings, client=MockEC2Client())
    result = scanner.scan()
    assert len(result.findings) == 2
    assert result.findings[0].severity == "Critical"


def test_ec2_scanner_correlates_public_ip_with_open_admin_ports():
    settings = Settings(use_mocks=True)
    scanner = EC2Scanner(settings, client=MockEC2Client())
    result = scanner.scan()
    assert len(result.findings) == 7
    assert {finding.issue for finding in result.findings} == {
        "IMDSv2 Not Enforced",
        "EC2 Instance Missing IAM Role",
        "Unencrypted EBS Volume Attached",
        "EC2 Instance Is Stopped",
        "EC2 Instance Has Public IP",
        "Public EC2 Instance Exposes SSH",
        "Public EC2 Instance Exposes RDP",
    }


def test_rds_scanner_detects_public_and_unencrypted_db():
    settings = Settings(use_mocks=True)
    scanner = RDSScanner(settings, client=MockRDSClient())
    result = scanner.scan()
    assert len(result.findings) == 2


def test_cloudtrail_scanner_detects_missing_trail():
    settings = Settings(use_mocks=True)
    scanner = CloudTrailScanner(settings, client=MockCloudTrailClient())
    result = scanner.scan()
    assert len(result.findings) == 1
    assert result.findings[0].service == "AWS CloudTrail"


def test_config_scanner_detects_disabled_recording():
    settings = Settings(use_mocks=True, enable_aws_config=True)
    scanner = AWSConfigScanner(settings, client=MockConfigClient())
    result = scanner.scan()
    assert len(result.findings) == 1
    assert result.findings[0].service == "AWS Config"


def test_nessus_scanner_detects_onprem_misconfigurations():
    settings = Settings(use_mocks=True)
    scanner = NessusOnPremScanner(settings, connector=MockNessusConnector())
    result = scanner.scan()
    assert result.scanned_resources == 1
    assert len(result.findings) == 6
    assert {finding.issue for finding in result.findings} == {
        "SMB Signing Not Enforced",
        "RDP Network Level Authentication Disabled",
        "Host Firewall Disabled",
        "Local Admin Password Rotation Missing",
        "Unsupported Operating System Detected",
        "Critical Patches Overdue",
    }
