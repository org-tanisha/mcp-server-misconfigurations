from __future__ import annotations

import boto3

from mcp_server.config import Settings
from utils.aws_client import AWSClientFactory


def test_settings_accept_endpoint_override():
    settings = Settings(aws_endpoint_url="http://localhost:4566", max_retries=3)
    assert settings.aws_endpoint_url == "http://localhost:4566"
    assert settings.max_retries == 3


def test_aws_client_factory_uses_endpoint_override():
    settings = Settings(aws_region="us-east-1", aws_endpoint_url="http://localhost:4566")
    factory = AWSClientFactory(settings)
    client = factory.client("s3")
    assert client.meta.endpoint_url.startswith("http://localhost:4566")


def test_settings_from_env_reads_static_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIA_TEST_KEY")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "test-token")
    settings = Settings.from_env()
    assert settings.aws_access_key_id == "AKIA_TEST_KEY"
    assert settings.aws_secret_access_key == "test-secret"
    assert settings.aws_session_token == "test-token"


def test_settings_from_env_reads_onprem_nessus_options(monkeypatch):
    monkeypatch.setenv("AWS_MCP_ENABLE_ONPREM_NESSUS", "true")
    monkeypatch.setenv("AWS_MCP_ONPREM_DATASET_PATH", "scanners\\data\\onprem_nessus_dataset.json")
    settings = Settings.from_env()
    assert settings.enable_onprem_nessus is True
    assert str(settings.onprem_dataset_path).endswith("scanners\\data\\onprem_nessus_dataset.json")


def test_aws_client_factory_prefers_static_credentials(monkeypatch):
    captured_kwargs = {}

    class FakeSession:
        def client(self, service_name, **kwargs):
            return type("FakeClient", (), {"service_name": service_name, "meta": type("Meta", (), {"endpoint_url": ""})()})()

    def fake_session_constructor(*args, **kwargs):
        captured_kwargs.update(kwargs)
        return FakeSession()

    monkeypatch.setattr(boto3.session, "Session", fake_session_constructor)

    settings = Settings(
        aws_region="us-east-1",
        aws_profile="aws-mcp-readonly",
        aws_access_key_id="AKIA_TEST_KEY",
        aws_secret_access_key="test-secret",
        aws_session_token="test-token",
    )
    AWSClientFactory(settings).client("ec2")
    assert captured_kwargs["aws_access_key_id"] == "AKIA_TEST_KEY"
    assert captured_kwargs["aws_secret_access_key"] == "test-secret"
    assert captured_kwargs["aws_session_token"] == "test-token"
    assert "profile_name" not in captured_kwargs
