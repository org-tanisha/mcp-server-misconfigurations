from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError
from mcp_server.config import Settings
from utils.aws_client import AWSClientFactory
from utils.models import ScanResult


class BaseScanner(ABC):
    scanner_name: str

    def __init__(self, settings: Settings):
        self.settings = settings
        self.client_factory = AWSClientFactory(settings)
        self.errors: list[str] = []

    @abstractmethod
    def scan(self) -> ScanResult:
        raise NotImplementedError

    def paginated_call(self, operation_name: str, result_key: str, **kwargs: Any) -> list[dict[str, Any]]:
        paginator = self.client.get_paginator(operation_name)
        items: list[dict[str, Any]] = []
        try:
            for page in paginator.paginate(**kwargs):
                items.extend(page.get(result_key, []))
        except (ClientError, BotoCoreError) as exc:
            self.errors.append(f"{self.scanner_name}:{operation_name}:{exc}")
        return items

    def safe_call(self, func, *args: Any, **kwargs: Any) -> Any:
        try:
            return func(*args, **kwargs)
        except (ClientError, BotoCoreError) as exc:
            self.errors.append(f"{self.scanner_name}:{func.__name__}:{exc}")
            return None
