from __future__ import annotations

from pathlib import Path
from pydantic import BaseModel, Field
import os


class Settings(BaseModel):
    aws_region: str = Field(default="us-east-1")
    aws_profile: str | None = Field(default=None)
    aws_profiles: list[str] = Field(default_factory=list)
    aws_access_key_id: str | None = Field(default=None)
    aws_secret_access_key: str | None = Field(default=None)
    aws_session_token: str | None = Field(default=None)
    use_mocks: bool = Field(default=False)
    enable_aws_config: bool = Field(default=False)
    enable_onprem_nessus: bool = Field(default=False)
    onprem_dataset_path: Path | None = Field(default=None)
    aws_endpoint_url: str | None = Field(default=None)
    output_dir: Path = Field(default=Path("reports"))
    history_dir: Path = Field(default=Path("reports/history"))
    project_name: str = Field(default="aws-mcp-misconfig-scanner")
    jira_url: str | None = Field(default=None)
    jira_user: str | None = Field(default=None)
    jira_token: str | None = Field(default=None)
    jira_project_key: str = Field(default="SEC")
    jira_issue_type: str = Field(default="Bug")
    max_retries: int = Field(default=5)

    @classmethod
    def from_env(cls) -> "Settings":
        output_dir = Path(os.getenv("AWS_MCP_OUTPUT_DIR", "reports"))
        profiles_env = os.getenv("AWS_PROFILES", "")
        aws_profile = os.getenv("AWS_PROFILE")
        aws_profiles = [item.strip() for item in profiles_env.split(",") if item.strip()]
        if not aws_profiles and aws_profile:
            aws_profiles = [aws_profile]
        return cls(
            aws_region=os.getenv("AWS_REGION", "us-east-1"),
            aws_profile=aws_profile,
            aws_profiles=aws_profiles,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            aws_session_token=os.getenv("AWS_SESSION_TOKEN"),
            use_mocks=os.getenv("AWS_MCP_USE_MOCKS", "false").lower() == "true",
            enable_aws_config=os.getenv("AWS_MCP_ENABLE_AWS_CONFIG", "false").lower() == "true",
            enable_onprem_nessus=os.getenv("AWS_MCP_ENABLE_ONPREM_NESSUS", "false").lower() == "true",
            onprem_dataset_path=(
                Path(dataset_path)
                if (dataset_path := os.getenv("AWS_MCP_ONPREM_DATASET_PATH"))
                else None
            ),
            aws_endpoint_url=os.getenv("AWS_ENDPOINT_URL"),
            output_dir=output_dir,
            history_dir=Path(os.getenv("AWS_MCP_HISTORY_DIR", str(output_dir / "history"))),
            jira_url=os.getenv("JIRA_URL"),
            jira_user=os.getenv("JIRA_USER"),
            jira_token=os.getenv("JIRA_TOKEN"),
            jira_project_key=os.getenv("JIRA_PROJECT_KEY", "SEC"),
            jira_issue_type=os.getenv("JIRA_ISSUE_TYPE", "Bug"),
            max_retries=int(os.getenv("AWS_MCP_MAX_RETRIES", "5")),
        )
