# Ransomware Response Engineering Lab

A defensive incident-response project for triaging suspected ransomware activity, preserving evidence, prioritizing containment, mapping observed behavior to MITRE ATT&CK, and validating recovery readiness using synthetic telemetry only.

> **Scope:** this repository contains no malware, encryption payloads, credential theft logic, exploit code, or production targeting. All datasets are synthetic and designed for defensive security engineering.

## Problem Statement

Ransomware incidents are rarely a single alert. Responders must correlate identity, endpoint, file-system, process, and network signals quickly enough to distinguish isolated suspicious behavior from a broader compromise while protecting evidence and avoiding unnecessary disruption.

This project implements a lightweight incident-triage engine that converts synthetic security events into explainable response findings and containment priorities. The goal is to demonstrate disciplined incident-response engineering rather than malware execution.

## Architecture

```text
Synthetic telemetry
      |
      v
Event normalization
      |
      v
Detection / correlation engine
      |
      +--> ATT&CK technique mapping
      +--> severity + confidence scoring
      +--> containment priority
      |
      v
Incident summary / response actions
      |
      v
Recovery and validation workflow
```

## Repository Structure

```text
.
├── src/
│   ├── models.py
│   ├── triage.py
│   └── reporting.py
├── tests/
│   └── test_triage.py
├── data/
│   └── synthetic-events.json
├── docs/
│   ├── architecture.md
│   ├── response-playbook.md
│   └── attack-mapping.md
├── reports/
│   └── example-incident-report.md
└── .github/workflows/tests.yml
```

## Detection and Response Logic

The current engine evaluates defensive indicators such as:

- burst file-renaming or file-write activity
- suspicious recovery-inhibition commands represented as telemetry metadata
- rapid propagation-like access across multiple hosts
- unusual privileged-account use during an incident window
- suspicious remote-service execution indicators
- endpoint security-control degradation events
- backup-service interference indicators
- high-volume access to sensitive file shares

Each finding includes:

- affected host or identity
- severity
- confidence
- supporting event IDs
- ATT&CK technique context
- recommended containment action
- validation criteria

## MITRE ATT&CK Context

The lab maps defensive observations to relevant techniques including:

- **T1486 — Data Encrypted for Impact**
- **T1490 — Inhibit System Recovery**
- **T1021 — Remote Services**
- **T1078 — Valid Accounts**
- **T1562.001 — Impair Defenses: Disable or Modify Tools**
- **T1083 — File and Directory Discovery**

ATT&CK mappings are used to structure defensive analysis and response coverage; they are not exploitation instructions.

## Example Usage

```bash
python -m src.triage data/synthetic-events.json
```

Example finding shape:

```json
{
  "finding_id": "RSP-001",
  "severity": "CRITICAL",
  "confidence": "HIGH",
  "asset": "ws-finance-07",
  "attack_techniques": ["T1486", "T1490"],
  "containment": "Isolate the endpoint while preserving volatile evidence and confirm backup integrity."
}
```

## Response Priorities

1. Confirm whether destructive or encryption-like activity is active.
2. Preserve volatile evidence before disruptive remediation where operationally feasible.
3. Isolate affected endpoints and restrict compromised identities.
4. Block validated malicious infrastructure or indicators using approved controls.
5. Protect backup infrastructure from compromised administrative paths.
6. Scope lateral movement and additional affected assets.
7. Eradicate persistence and close the initial-access path.
8. Restore from validated clean recovery points.
9. Re-enable controls in a monitored state.
10. Conduct post-incident validation and lessons learned.

## Testing

```bash
python -m unittest discover -s tests -v
```

The unit tests validate correlation behavior, severity assignment, ATT&CK mappings, evidence references, and handling of low-risk background telemetry.

## CI/CD

GitHub Actions executes the dependency-free unit-test suite on pushes and pull requests. CI presence is not treated as evidence of a passing workflow unless the run is independently verified.

## Skills Demonstrated

- incident response engineering
- ransomware triage methodology
- detection correlation
- MITRE ATT&CK mapping
- evidence-aware containment
- Python security automation
- synthetic telemetry design
- remediation and recovery validation
- security reporting
- unit testing and CI/CD

## Limitations

This repository is intentionally a synthetic lab. It does not claim malware reverse engineering, live EDR integration, forensic acquisition, production containment authority, threat-actor attribution, or real-world incident handling.

## Roadmap

- add host/identity incident graphing
- add configurable response thresholds
- add evidence-chain metadata validation
- add case-state tracking
- add Sigma-rule compatibility examples
- add JSON and Markdown report export
- add recovery-readiness scoring

## Ethical Use

Use only for defensive learning, authorized security validation, and portfolio demonstration. Do not use the concepts in this repository to disrupt, encrypt, damage, or access systems without explicit authorization.
