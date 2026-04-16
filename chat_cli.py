from __future__ import annotations

import json
import os
import sys

from llm_interface.assistant import LLMSecurityAssistant
from mcp_server.config import Settings


def main() -> None:
    if not os.getenv("GEMINI_API_KEY"):
        raise SystemExit("GEMINI_API_KEY is not set.")

    prompt = " ".join(sys.argv[1:]).strip()
    if not prompt:
        raise SystemExit("Usage: python chat_cli.py \"Scan my AWS environment for misconfigurations.\"")

    assistant = LLMSecurityAssistant(Settings.from_env())
    result = assistant.answer(prompt)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
