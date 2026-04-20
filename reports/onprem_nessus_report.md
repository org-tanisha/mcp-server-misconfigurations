# Misconfiguration Report

Generated at: 2026-04-20T05:01:50.931998+00:00

## Executive Summary

The scan identified AWS configuration issues that increase exposure to data loss, unauthorized access, and audit findings. Priority should be given to internet-exposed resources, weak IAM controls, and logging gaps.

- Total findings: 30
- Critical: 9
- High: 21
- Medium: 0
- Low: 0

## Severity Breakdown

- Critical: 9
- High: 21

## Service Breakdown

- On-Prem Infrastructure (Nessus): 30

## CIS Control Gaps

- 12.2
- 4.8
- 5.4
- 6.3
- 7.3
- 7.7

## Top Risks

### Unsupported Operating System Detected
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-web-01
- Severity: Critical
- CIS Control: 7.7
- Risk Score: 96
- Recommendation: Migrate unsupported operating systems to supported versions.

### Unsupported Operating System Detected
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-jump-01
- Severity: Critical
- CIS Control: 7.7
- Risk Score: 96
- Recommendation: Migrate unsupported operating systems to supported versions.

### Unsupported Operating System Detected
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-ad-01
- Severity: Critical
- CIS Control: 7.7
- Risk Score: 96
- Recommendation: Migrate unsupported operating systems to supported versions.

### Unsupported Operating System Detected
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-backup-01
- Severity: Critical
- CIS Control: 7.7
- Risk Score: 96
- Recommendation: Migrate unsupported operating systems to supported versions.

### Host Firewall Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-web-01
- Severity: Critical
- CIS Control: 12.2
- Risk Score: 92
- Recommendation: Enable host-based firewalls and enforce baseline inbound rules.

## Full Findings

### SMB Signing Not Enforced
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-web-01
- Severity: High
- CIS Control: 4.8
- Risk Score: 84
- Recommendation: Enforce SMB signing on all on-prem Windows servers.

### RDP Network Level Authentication Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-web-01
- Severity: High
- CIS Control: 6.3
- Risk Score: 86
- Recommendation: Require Network Level Authentication (NLA) for all RDP endpoints.

### Host Firewall Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-web-01
- Severity: Critical
- CIS Control: 12.2
- Risk Score: 92
- Recommendation: Enable host-based firewalls and enforce baseline inbound rules.

### Local Admin Password Rotation Missing
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-web-01
- Severity: High
- CIS Control: 5.4
- Risk Score: 83
- Recommendation: Implement local administrator password rotation (for example via Microsoft LAPS).

### Unsupported Operating System Detected
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-web-01
- Severity: Critical
- CIS Control: 7.7
- Risk Score: 96
- Recommendation: Migrate unsupported operating systems to supported versions.

### Critical Patches Overdue
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-web-01
- Severity: High
- CIS Control: 7.3
- Risk Score: 88
- Recommendation: Apply overdue security patches within the defined remediation SLA.

### SMB Signing Not Enforced
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-jump-01
- Severity: High
- CIS Control: 4.8
- Risk Score: 84
- Recommendation: Enforce SMB signing on all on-prem Windows servers.

### RDP Network Level Authentication Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-jump-01
- Severity: High
- CIS Control: 6.3
- Risk Score: 86
- Recommendation: Require Network Level Authentication (NLA) for all RDP endpoints.

### Local Admin Password Rotation Missing
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-jump-01
- Severity: High
- CIS Control: 5.4
- Risk Score: 83
- Recommendation: Implement local administrator password rotation (for example via Microsoft LAPS).

### Unsupported Operating System Detected
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-jump-01
- Severity: Critical
- CIS Control: 7.7
- Risk Score: 96
- Recommendation: Migrate unsupported operating systems to supported versions.

### Critical Patches Overdue
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-jump-01
- Severity: High
- CIS Control: 7.3
- Risk Score: 88
- Recommendation: Apply overdue security patches within the defined remediation SLA.

### SMB Signing Not Enforced
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-ad-01
- Severity: High
- CIS Control: 4.8
- Risk Score: 84
- Recommendation: Enforce SMB signing on all on-prem Windows servers.

### Host Firewall Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-ad-01
- Severity: Critical
- CIS Control: 12.2
- Risk Score: 92
- Recommendation: Enable host-based firewalls and enforce baseline inbound rules.

### Local Admin Password Rotation Missing
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-ad-01
- Severity: High
- CIS Control: 5.4
- Risk Score: 83
- Recommendation: Implement local administrator password rotation (for example via Microsoft LAPS).

### Unsupported Operating System Detected
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-ad-01
- Severity: Critical
- CIS Control: 7.7
- Risk Score: 96
- Recommendation: Migrate unsupported operating systems to supported versions.

### Critical Patches Overdue
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-ad-01
- Severity: High
- CIS Control: 7.3
- Risk Score: 88
- Recommendation: Apply overdue security patches within the defined remediation SLA.

### SMB Signing Not Enforced
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-files-01
- Severity: High
- CIS Control: 4.8
- Risk Score: 84
- Recommendation: Enforce SMB signing on all on-prem Windows servers.

### Critical Patches Overdue
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-files-01
- Severity: High
- CIS Control: 7.3
- Risk Score: 88
- Recommendation: Apply overdue security patches within the defined remediation SLA.

### Host Firewall Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-linux-bastion-01
- Severity: Critical
- CIS Control: 12.2
- Risk Score: 92
- Recommendation: Enable host-based firewalls and enforce baseline inbound rules.

### Local Admin Password Rotation Missing
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-linux-bastion-01
- Severity: High
- CIS Control: 5.4
- Risk Score: 83
- Recommendation: Implement local administrator password rotation (for example via Microsoft LAPS).

### Critical Patches Overdue
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-linux-bastion-01
- Severity: High
- CIS Control: 7.3
- Risk Score: 88
- Recommendation: Apply overdue security patches within the defined remediation SLA.

### RDP Network Level Authentication Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-vdi-01
- Severity: High
- CIS Control: 6.3
- Risk Score: 86
- Recommendation: Require Network Level Authentication (NLA) for all RDP endpoints.

### Host Firewall Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-vdi-01
- Severity: Critical
- CIS Control: 12.2
- Risk Score: 92
- Recommendation: Enable host-based firewalls and enforce baseline inbound rules.

### Critical Patches Overdue
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-vdi-01
- Severity: High
- CIS Control: 7.3
- Risk Score: 88
- Recommendation: Apply overdue security patches within the defined remediation SLA.

### Unsupported Operating System Detected
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-backup-01
- Severity: Critical
- CIS Control: 7.7
- Risk Score: 96
- Recommendation: Migrate unsupported operating systems to supported versions.

### SMB Signing Not Enforced
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-printer-mgmt-01
- Severity: High
- CIS Control: 4.8
- Risk Score: 84
- Recommendation: Enforce SMB signing on all on-prem Windows servers.

### RDP Network Level Authentication Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-printer-mgmt-01
- Severity: High
- CIS Control: 6.3
- Risk Score: 86
- Recommendation: Require Network Level Authentication (NLA) for all RDP endpoints.

### Host Firewall Disabled
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-printer-mgmt-01
- Severity: Critical
- CIS Control: 12.2
- Risk Score: 92
- Recommendation: Enable host-based firewalls and enforce baseline inbound rules.

### Local Admin Password Rotation Missing
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-printer-mgmt-01
- Severity: High
- CIS Control: 5.4
- Risk Score: 83
- Recommendation: Implement local administrator password rotation (for example via Microsoft LAPS).

### Critical Patches Overdue
- Service: On-Prem Infrastructure (Nessus)
- Resource: onprem-printer-mgmt-01
- Severity: High
- CIS Control: 7.3
- Risk Score: 88
- Recommendation: Apply overdue security patches within the defined remediation SLA.
