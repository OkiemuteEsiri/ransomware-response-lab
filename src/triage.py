import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Iterable, List

from src.models import Finding, SecurityEvent


SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _event(raw: dict) -> SecurityEvent:
    return SecurityEvent(
        event_id=raw["event_id"],
        timestamp=raw["timestamp"],
        event_type=raw["event_type"],
        asset=raw["asset"],
        actor=raw.get("actor", ""),
        target=raw.get("target", ""),
        count=int(raw.get("count", 1)),
        severity_hint=raw.get("severity_hint", "LOW").upper(),
        details=raw.get("details", {}),
    )


def load_events(path: str) -> List[SecurityEvent]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Telemetry input must be a JSON list")
    return [_event(item) for item in data]


def analyze(events: Iterable[SecurityEvent]) -> List[Finding]:
    by_asset = defaultdict(list)
    for event in events:
        by_asset[event.asset].append(event)

    findings: List[Finding] = []
    counter = 1

    for asset, asset_events in sorted(by_asset.items()):
        ids = lambda selected: [e.event_id for e in selected]

        destructive = [e for e in asset_events if e.event_type in {"mass_file_change", "recovery_inhibition"}]
        if destructive:
            techniques = []
            if any(e.event_type == "mass_file_change" for e in destructive):
                techniques.append("T1486")
            if any(e.event_type == "recovery_inhibition" for e in destructive):
                techniques.append("T1490")
            severity = "CRITICAL" if len(set(e.event_type for e in destructive)) > 1 else "HIGH"
            findings.append(Finding(
                finding_id=f"RSP-{counter:03d}",
                title="Potential destructive ransomware activity",
                severity=severity,
                confidence="HIGH",
                asset=asset,
                attack_techniques=techniques,
                evidence_event_ids=ids(destructive),
                containment="Isolate the endpoint through approved response controls while preserving volatile evidence where feasible.",
                validation="Confirm destructive activity has stopped, validate backup integrity, and verify no additional affected hosts are present.",
            ))
            counter += 1

        remote = [e for e in asset_events if e.event_type in {"remote_service_execution", "multi_host_access"}]
        if remote:
            findings.append(Finding(
                finding_id=f"RSP-{counter:03d}",
                title="Possible lateral movement or propagation",
                severity="HIGH",
                confidence="MEDIUM" if len(remote) == 1 else "HIGH",
                asset=asset,
                attack_techniques=["T1021", "T1078"],
                evidence_event_ids=ids(remote),
                containment="Restrict the implicated identity and remote-management path, then scope peer hosts for related activity.",
                validation="Verify remote access has ceased and review authentication telemetry for additional affected systems.",
            ))
            counter += 1

        impaired = [e for e in asset_events if e.event_type in {"security_control_disabled", "backup_interference"}]
        if impaired:
            techniques = ["T1562.001"]
            if any(e.event_type == "backup_interference" for e in impaired):
                techniques.append("T1490")
            findings.append(Finding(
                finding_id=f"RSP-{counter:03d}",
                title="Security or recovery controls impaired",
                severity="HIGH",
                confidence="HIGH",
                asset=asset,
                attack_techniques=sorted(set(techniques)),
                evidence_event_ids=ids(impaired),
                containment="Protect security and backup control planes from the affected host or identity and restore approved protections.",
                validation="Confirm controls are healthy, tamper protection is restored, and recovery services are independently reachable.",
            ))
            counter += 1

        discovery = [e for e in asset_events if e.event_type == "sensitive_share_enumeration" and e.count >= 25]
        if discovery:
            findings.append(Finding(
                finding_id=f"RSP-{counter:03d}",
                title="High-volume sensitive file-share discovery",
                severity="MEDIUM",
                confidence="MEDIUM",
                asset=asset,
                attack_techniques=["T1083"],
                evidence_event_ids=ids(discovery),
                containment="Review the initiating identity and constrain unnecessary share access while the incident is scoped.",
                validation="Confirm access patterns return to baseline and permissions match approved business need.",
            ))
            counter += 1

    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.asset, f.finding_id))


def summarize(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    return {
        "total_findings": len(findings),
        "severity_counts": counts,
        "critical_assets": sorted({f.asset for f in findings if f.severity == "CRITICAL"}),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python -m src.triage <events.json>")
        return 2
    findings = analyze(load_events(sys.argv[1]))
    payload = {
        "summary": summarize(findings),
        "findings": [f.__dict__ for f in findings],
    }
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
