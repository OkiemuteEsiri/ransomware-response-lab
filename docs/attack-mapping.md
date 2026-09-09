# MITRE ATT&CK Mapping

This mapping is for defensive coverage planning. It links synthetic observations to ATT&CK techniques without asserting exploitation success or threat-actor attribution.

| Observation | ATT&CK | Defensive interpretation |
|---|---|---|
| Burst destructive file modification | T1486 — Data Encrypted for Impact | Potential destructive impact requiring rapid containment and recovery validation |
| Recovery-service interference | T1490 — Inhibit System Recovery | Possible attempt to reduce restore options or recovery resilience |
| Remote-service activity during incident window | T1021 — Remote Services | Potential lateral movement or propagation path |
| Suspicious use of legitimate accounts | T1078 — Valid Accounts | Identity compromise or misuse requiring account scoping and restriction |
| Endpoint protection disabled or modified | T1562.001 — Impair Defenses | Security control degradation that increases response urgency |
| High-volume file/share discovery | T1083 — File and Directory Discovery | Reconnaissance or staging behavior supporting scope analysis |

## Coverage Questions

For each mapped technique, analysts should ask:

1. What telemetry confirms or disproves the behavior?
2. Which assets and identities are affected?
3. Is the behavior isolated or repeated across the environment?
4. Which detection or prevention control should have observed it?
5. What remediation closes the underlying exposure?
6. What evidence demonstrates successful revalidation?

## Interpretation Limits

ATT&CK mappings describe behavior categories, not intent. A single event may have a legitimate administrative explanation. Confidence should increase only when supporting telemetry and contextual evidence align.
