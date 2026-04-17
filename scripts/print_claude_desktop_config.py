from __future__ import annotations

from pathlib import Path
import json


ROOT = Path(__file__).resolve().parents[1]
PYTHON_EXE = ROOT / ".venv" / "Scripts" / "python.exe"
# We'll use the robust unified launcher for better reliability and logging
UNIFIED_LAUNCHER = ROOT / "robust_unified_launcher.py"


def main() -> None:
    config = {
        "mcpServers": {
            "security-scanner-unified": {
                "command": str(PYTHON_EXE),
                "args": [str(UNIFIED_LAUNCHER)],
                "cwd": str(ROOT),
                "env": {
                    "AWS_PROFILE": "default",
                    "AWS_PROFILES": "default",
                    "AWS_REGION": "us-east-1",
                    "AWS_MCP_USE_MOCKS": "true",
                    "AWS_MCP_ENABLE_AWS_CONFIG": "true",
                    "AWS_MCP_ENABLE_ONPREM_NESSUS": "true",
                    "AWS_MCP_ONPREM_DATASET_PATH": str(ROOT / "scanners" / "data" / "onprem_nessus_dataset.json"),
                    "AWS_MCP_OUTPUT_DIR": str(ROOT / "reports"),
                    "AWS_MCP_HISTORY_DIR": str(ROOT / "reports" / "history"),
                },
            }
        }
    }
    print(json.dumps(config, indent=2))


if __name__ == "__main__":
    main()
