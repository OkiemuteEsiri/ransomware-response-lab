import unittest

from src.models import SecurityEvent
from src.triage import analyze, summarize


class TriageTests(unittest.TestCase):
    def test_destructive_pair_is_critical(self):
        events = [
            SecurityEvent("e1", "2026-09-01T10:00:00Z", "mass_file_change", "host-a"),
            SecurityEvent("e2", "2026-09-01T10:01:00Z", "recovery_inhibition", "host-a"),
        ]
        findings = analyze(events)
        self.assertEqual(findings[0].severity, "CRITICAL")
        self.assertEqual(set(findings[0].attack_techniques), {"T1486", "T1490"})

    def test_remote_activity_maps_lateral_movement(self):
        events = [SecurityEvent("e3", "2026-09-01T10:00:00Z", "remote_service_execution", "host-b")]
        findings = analyze(events)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertIn("T1021", findings[0].attack_techniques)
        self.assertIn("T1078", findings[0].attack_techniques)

    def test_control_impairment_generates_evidence_reference(self):
        events = [SecurityEvent("e4", "2026-09-01T10:00:00Z", "security_control_disabled", "host-c")]
        findings = analyze(events)
        self.assertEqual(findings[0].evidence_event_ids, ["e4"])
        self.assertIn("T1562.001", findings[0].attack_techniques)

    def test_background_event_does_not_generate_finding(self):
        events = [SecurityEvent("e5", "2026-09-01T10:00:00Z", "normal_login", "host-d")]
        self.assertEqual(analyze(events), [])

    def test_summary_tracks_critical_assets(self):
        events = [
            SecurityEvent("e6", "2026-09-01T10:00:00Z", "mass_file_change", "host-e"),
            SecurityEvent("e7", "2026-09-01T10:01:00Z", "recovery_inhibition", "host-e"),
        ]
        summary = summarize(analyze(events))
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(summary["critical_assets"], ["host-e"])


if __name__ == "__main__":
    unittest.main()
