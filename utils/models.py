from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    service: str
    resource_id: str
    issue: str
    severity: str
    compliance_standard: str
    risk_description: str
    recommendation: str
    remediation_steps: list[str]
    cis_control_id: str
    nist_csf: list[str] = Field(default_factory=list)
    owasp_category: str | None = None
    risk_score: int = 0
    metadata: dict[str, str | int | bool] = Field(default_factory=dict)


class ScanResult(BaseModel):
    scanner: str
    findings: list[Finding]
    scanned_resources: int = 0
    status: str = "completed"
    errors: list[str] = Field(default_factory=list)


class ExecutiveSummary(BaseModel):
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    top_risks: list[str]
    compliance_gaps: list[str]
    service_breakdown: dict[str, int] = Field(default_factory=dict)
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    summary: str
