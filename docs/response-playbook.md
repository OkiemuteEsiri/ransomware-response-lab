# Ransomware Response and Recovery Playbook

## Purpose

Provide a structured defensive workflow for suspected ransomware incidents using synthetic evidence. Actions must be adapted to organizational authority, legal requirements, business continuity plans, and approved incident-response procedures.

## Phase 1 — Validate and Preserve

1. Confirm alert provenance and affected asset identity.
2. Capture relevant event IDs, timestamps, account context, and detection metadata.
3. Preserve volatile evidence before disruptive action when operationally feasible.
4. Record who authorized containment and when.
5. Avoid deleting files, wiping systems, or destroying artifacts before evidence requirements are understood.

## Phase 2 — Contain

Prioritize containment by business impact and destructive activity:

- isolate actively affected endpoints through approved EDR/network controls
- restrict identities linked to suspicious remote activity
- protect privileged accounts and administrative paths
- isolate backup infrastructure from potentially compromised credentials
- block validated malicious indicators through approved security controls
- segment affected systems from critical services where necessary

Containment should be reversible, documented, and proportionate to the evidence.

## Phase 3 — Scope

Review:

- authentication activity for implicated identities
- remote-service telemetry across peer systems
- file-share access and bulk file operations
- endpoint protection health
- backup-platform administrative events
- privileged-account usage
- security-control changes
- related alerts before and after the initial detection window

## Phase 4 — Eradicate

Eradication begins only after scope is sufficiently understood. Defensive objectives include removing persistence, resetting compromised credentials, restoring disabled security controls, patching or hardening the initial-access path, and validating that affected systems no longer show related behavior.

## Phase 5 — Recover

1. Validate recovery points before restoration.
2. Rebuild or restore systems according to approved recovery standards.
3. Rotate credentials that may have been exposed.
4. Re-enable endpoint, network, identity, and logging controls.
5. Monitor restored systems at elevated scrutiny.
6. Confirm business service health with service owners.

## Phase 6 — Validate Closure

Closure criteria should include:

- no continuing destructive activity
- no unexplained remote-access events
- security controls healthy and reporting
- backup integrity independently confirmed
- compromised credentials rotated or revoked
- initial-access weakness remediated
- peer assets checked for related indicators
- recovery validated by service owners
- lessons learned and detection gaps documented

## Escalation Triggers

Escalate immediately when evidence suggests domain-wide identity compromise, backup-platform compromise, critical-service disruption, destructive activity on multiple hosts, regulated-data exposure, or uncertainty that containment is holding.
