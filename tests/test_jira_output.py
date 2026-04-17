import json
from mcp_server.config import Settings
from mcp_server.tools import ToolRegistry
from utils.models import Finding

def test_jira_payload_generation():
    # 1. Setup settings (using defaults)
    settings = Settings()
    registry = ToolRegistry(settings)
    
    # 2. Create a mock finding
    mock_finding = {
        "service": "S3",
        "resource_id": "my-test-bucket",
        "issue": "Public Read Access Enabled",
        "severity": "High",
        "compliance_standard": "CIS AWS Foundations 1.2.0",
        "risk_description": "Allowing public read access to S3 buckets can lead to data exposure.",
        "recommendation": "Disable public access in bucket policy.",
        "remediation_steps": [
            "Go to S3 Console",
            "Select bucket 'my-test-bucket'",
            "Permissions tab -> Block public access"
        ],
        "cis_control_id": "2.1.1",
        "risk_score": 8,
        "metadata": {"region": "us-east-1"}
    }
    
    print("--- Generating Jira Payload for Mock Finding ---")
    payload = registry.generate_jira_ticket_payload(mock_finding)
    print(json.dumps(payload, indent=2))
    
    # 3. Verify key fields
    assert payload["fields"]["project"]["key"] == settings.jira_project_key
    assert "S3" in payload["fields"]["summary"]
    assert "Public Read Access" in payload["fields"]["summary"]
    assert payload["fields"]["priority"]["name"] == "High"
    
    print("\nSUCCESS: Jira JSON payload generated correctly.")

if __name__ == "__main__":
    try:
        test_jira_payload_generation()
    except Exception as e:
        print(f"FAILURE: {e}")
