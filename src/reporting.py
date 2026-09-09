from typing import Iterable

from src.models import Finding
from src.triage import summarize


def to_markdown(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    summary = summarize(findings)
    lines = [
        "# Ransomware Response Assessment",
        "",
        f"Total findings: **{summary['total_findings']}**",
        "",
        "## Severity Summary",
        "",
    ]
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        lines.append(f"- {severity}: {summary['severity_counts'][severity]}")

    lines.extend(["", "## Findings", ""])
    for finding in findings:
        lines.extend([
            f"### {finding.finding_id} — {finding.title}",
            f"- Asset: `{finding.asset}`",
            f"- Severity: **{finding.severity}**",
            f"- Confidence: {finding.confidence}",
            f"- ATT&CK: {', '.join(finding.attack_techniques)}",
            f"- Evidence: {', '.join(finding.evidence_event_ids)}",
            f"- Containment: {finding.containment}",
            f"- Validation: {finding.validation}",
            "",
        ])
    return "\n".join(lines)
