# Architecture

## Objective

Provide an explainable, dependency-light incident-response pipeline for synthetic ransomware-related telemetry. The design separates event representation, correlation, prioritization, reporting, and response validation so each control can be reviewed independently.

## Components

### 1. Event model
`src/models.py` defines immutable security events and findings. Evidence references are carried forward into every finding to preserve analytical traceability.

### 2. Triage engine
`src/triage.py` groups telemetry by asset and applies defensive correlations for destructive activity, remote-access propagation, security-control impairment, backup interference, and sensitive-share discovery.

### 3. Risk normalization
Findings use LOW, MEDIUM, HIGH, and CRITICAL severities. Severity reflects response urgency, while confidence reflects evidence strength. The two are deliberately kept separate.

### 4. ATT&CK mapping
Observed behavior is mapped to ATT&CK techniques for defensive coverage and communication. Technique mappings do not imply successful exploitation or threat-actor attribution.

### 5. Reporting
`src/reporting.py` converts findings into a human-readable Markdown assessment containing evidence IDs, containment actions, and validation criteria.

## Trust Boundaries

The project assumes all input is untrusted analytical data. Production ingestion, EDR APIs, identity-provider APIs, and case-management integrations are intentionally excluded from this lab.

## Design Principles

- evidence traceability over opaque scoring
- containment guidance without destructive automation
- synthetic data only
- explainable ATT&CK mappings
- dependency-light code for recruiter review
- testable correlations
- explicit separation between observation, inference, and response action
