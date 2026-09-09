from dataclasses import dataclass, field
from typing import List


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: str
    event_type: str
    asset: str
    actor: str = ""
    target: str = ""
    count: int = 1
    severity_hint: str = "LOW"
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    confidence: str
    asset: str
    attack_techniques: List[str]
    evidence_event_ids: List[str]
    containment: str
    validation: str
