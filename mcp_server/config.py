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
            max_retries=int(os.getenv("AWS_MCP_MAX_RETRIES", "5")),
        )
{
   "mcpServers": {
     "aws-misconfig-scanner": {
       "command": "C:\\Users\\HP\\OneDrive\\Desktop\\mcp\\.venv\\Scripts\\python.exe",
       "args": ["C:\\Users\\HP\\OneDrive\\Desktop\\mcp\\claude_launcher.py"],
       "cwd": "C:\\Users\\HP\\OneDrive\\Desktop\\mcp",
       "env": {
         "AWS_PROFILE": "aws-mcp-readonly",
         "AWS_PROFILES": "aws-mcp-readonly",
         "AWS_REGION": "us-east-1",
         "AWS_MCP_USE_MOCKS": "false",
         "AWS_MCP_ENABLE_AWS_CONFIG": "true"
       }
     },
     "nessus-onprem-scanner": {
       "command": "C:\\Users\\HP\\OneDrive\\Desktop\\mcp\\.venv\\Scripts\\python.exe",
       "args": ["C:\\Users\\HP\\OneDrive\\Desktop\\mcp\\claude_nessus_launcher.py"],
       "cwd": "C:\\Users\\HP\\OneDrive\\Desktop\\mcp",
       "env": {
         "AWS_MCP_USE_MOCKS": "true",
         "AWS_MCP_ENABLE_ONPREM_NESSUS": "true",
         "AWS_MCP_ONPREM_DATASET_PATH": "scanners\\data\\onprem_nessus_dataset.json"
       }
     }
   }
 }
