import json
from pathlib import Path
import unittest
from cloudops_toolkit.logs import analyze_access_log
from cloudops_toolkit.reports import build_incident_report
ROOT = Path(__file__).resolve().parents[1]

class TestReports(unittest.TestCase):
    def test_incident_report_contains_evidence_and_uncertainty(self):
        health = json.loads((ROOT / "samples" / "demo-health.json").read_text(encoding="utf-8"))
        logs = analyze_access_log(ROOT / "samples" / "access.log")
        report = build_incident_report(health, logs)
        self.assertIn("Root cause:** Unconfirmed", report)
        self.assertIn("HTTP 5xx responses: **4**", report)
        self.assertIn("/api/orders", report)
        self.assertNotIn("token=", report)
