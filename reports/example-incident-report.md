# Example Incident Report — Synthetic Ransomware Response

> This report is generated from synthetic laboratory telemetry and does not represent a real incident, employer, client, user, or production environment.

## Executive Summary

The synthetic dataset contains a high-confidence destructive-activity pattern on `ws-finance-07`, accompanied by recovery-inhibition telemetry, endpoint-protection degradation, suspicious remote activity, and sensitive-share discovery. Separate telemetry also indicates backup-service interference on `srv-backup-01` and remote-service activity on `srv-files-02`.

The modeled response priority is to contain the actively affected workstation, restrict the implicated identity, protect backup infrastructure, and scope remote-access activity across peer systems before restoration.

## Priority Findings

### Critical — Potential destructive ransomware activity
- Asset: `ws-finance-07`
- Evidence: `evt-001`, `evt-002`
- ATT&CK: T1486, T1490
- Response: isolate using approved controls while preserving evidence where feasible
- Validation: confirm destructive activity has ceased and backup integrity remains intact

### High — Security control impairment
- Asset: `ws-finance-07`
- Evidence: `evt-003`
- ATT&CK: T1562.001
- Response: restore endpoint controls and review the administrative path used to alter them

### High — Possible propagation/lateral movement
- Assets: `ws-finance-07`, `srv-files-02`
- Evidence: `evt-004`, `evt-005`
- ATT&CK: T1021, T1078
- Response: restrict implicated identity and scope peer systems for related authentication or remote-service telemetry

### High — Backup/recovery control interference
- Asset: `srv-backup-01`
- Evidence: `evt-006`
- ATT&CK: T1490, T1562.001
- Response: protect backup administrative paths and independently validate recovery services

### Medium — Sensitive-share discovery
- Asset: `ws-finance-07`
- Evidence: `evt-007`
- ATT&CK: T1083
- Response: review share access, identity context, and business justification

## Recovery Validation Checklist

- affected hosts isolated or rebuilt according to approved process
- implicated credentials revoked or rotated
- endpoint protection healthy
- backup integrity verified independently
- no unexplained related remote-access events
- initial-access weakness remediated
- peer hosts checked for related indicators
- service owner confirms operational recovery

## Residual Risk

Residual risk remains elevated until lateral-movement scope, identity exposure, and backup integrity are fully validated. Restoration alone does not establish incident closure.
