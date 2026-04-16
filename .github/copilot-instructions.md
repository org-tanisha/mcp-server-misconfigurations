# Copilot Instructions

## Build, test, lint, and run commands

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

```powershell
pytest -q
```

```powershell
pytest tests\test_scanners.py::test_s3_scanner_detects_three_findings -q
pytest tests\test_llm_assistant.py::test_answer_calls_gemini_and_returns_text -q
```

```powershell
python main.py
python claude_launcher.py
python chat_cli.py "Scan my AWS environment and summarize the most urgent risks."
```

No dedicated lint command is currently configured in this repository or CI workflow.

## High-level architecture

- `main.py` and `claude_launcher.py` are thin entrypoints that both call `mcp_server.server.build_server()`, but run with different transports (`run()` vs `run("stdio")`).
- `mcp_server/server.py` wires MCP tool exposure directly to `ToolRegistry` methods in `mcp_server/tools.py`.
- `ToolRegistry` is the orchestration layer: it composes all service scanners, optionally includes AWS Config scanning, annotates findings for multi-profile scans, and owns report/history generation.
- `scanners/*.py` perform AWS evidence collection and return `ScanResult` with normalized `Finding` objects; shared scanner behavior lives in `scanners/base.py`.
- `rules/cis_rules.py` is the single source of truth for severity/risk/compliance metadata; scanners should emit findings via `build_finding(...)`.
- `utils/reporting.py` turns findings into JSON/Markdown artifacts and historical trend summaries under `reports\` and `reports\history\`.
- `llm_interface/assistant.py` gives Gemini function-calling access to the same `ToolRegistry` handlers used by MCP, so assistant behavior stays aligned with server tools.
- Runtime configuration is environment-driven through `Settings.from_env()` in `mcp_server/config.py` (AWS profile selection, optional AWS Config scanner, LocalStack endpoint, output/history directories, retries, LLM model).

## Key conventions in this repository

- Keep scanner logic focused on AWS API evidence collection; centralize compliance and severity mapping in `rules/cis_rules.py`.
- New scanner/tool features must be wired through all three integration points:
  1. `ToolRegistry` implementation (`mcp_server/tools.py`)
  2. MCP registration (`mcp_server/server.py`)
  3. LLM tool exposure (`llm_interface/assistant.py::tool_handlers`)
- Follow the existing scanner error-handling pattern: use `safe_call(...)` / `paginated_call(...)`, append scanner-qualified errors, and still return a `ScanResult`.
- Preserve typed boundaries: internal code passes `Finding`/`ScanResult` models; MCP-returned payloads are `model_dump()` dictionaries.
- Use environment-driven configuration via `Settings.from_env()` (`AWS_PROFILE`, `AWS_PROFILES`, `AWS_MCP_ENABLE_AWS_CONFIG`, `AWS_ENDPOINT_URL`, report/history dirs, retry count, `LLM_MODEL`).
- Preserve existing behavior where `scan_ec2_misconfigurations` includes both EC2 findings and security-group findings; standalone SG scanning also exists via `scan_security_groups`.
- Multi-account scans are profile-driven (`AWS_PROFILES` / `AWS_PROFILE`) and findings are tagged with `metadata.aws_profile` before aggregation/history persistence.
- Unit tests are offline-first and rely on injected fake clients/stub registries (`tests/test_scanners.py`, `tests/test_llm_assistant.py`, `tests/test_phase7_enterprise.py`), so extend tests with deterministic stubs instead of live AWS calls.
