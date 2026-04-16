$ErrorActionPreference = "Stop"

$env:AWS_REGION = "us-east-1"
$env:AWS_ACCESS_KEY_ID = "test"
$env:AWS_SECRET_ACCESS_KEY = "test"
$env:AWS_MCP_USE_MOCKS = "false"
$env:AWS_MCP_ENABLE_AWS_CONFIG = "true"
$env:AWS_ENDPOINT_URL = "http://localhost:4566"

Write-Host "Starting LocalStack-backed scan configuration..."
Write-Host "AWS_ENDPOINT_URL=$env:AWS_ENDPOINT_URL"
Write-Host "Run 'docker compose -f docker-compose.localstack.yml up --build' in another shell if services are not already running."
Write-Host "Then run '.\.venv\Scripts\python.exe main.py' to start the MCP server against LocalStack."

