from __future__ import annotations

from dataclasses import dataclass
import boto3
from botocore.config import Config

from mcp_server.config import Settings


@dataclass
class AWSClientFactory:
    settings: Settings

    def session(self) -> boto3.session.Session:
        if self.settings.aws_access_key_id and self.settings.aws_secret_access_key:
            return boto3.session.Session(
                aws_access_key_id=self.settings.aws_access_key_id,
                aws_secret_access_key=self.settings.aws_secret_access_key,
                aws_session_token=self.settings.aws_session_token,
                region_name=self.settings.aws_region,
            )
        if self.settings.aws_profile:
            return boto3.session.Session(
                profile_name=self.settings.aws_profile,
                region_name=self.settings.aws_region,
            )
        return boto3.session.Session(region_name=self.settings.aws_region)

    def client(self, service_name: str):
        retry_config = Config(
            retries={
                "max_attempts": self.settings.max_retries,
                "mode": "standard",
            }
        )
        client_kwargs = {"config": retry_config}
        if self.settings.aws_endpoint_url:
            client_kwargs["endpoint_url"] = self.settings.aws_endpoint_url
            if service_name == "s3":
                client_kwargs["config"] = Config(
                    retries={
                        "max_attempts": self.settings.max_retries,
                        "mode": "standard",
                    },
                    s3={"addressing_style": "path"},
                )
        return self.session().client(service_name, **client_kwargs)
