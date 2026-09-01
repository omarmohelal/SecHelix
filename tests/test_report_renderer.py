import copy
import json
import unittest
from pathlib import Path

from reports.report_renderer import ReportValidationError, render_html, render_json, render_markdown, render_sarif


ROOT = Path(__file__).resolve().parents[1]

LEGACY_REPORT = {
    "schema_version": "1.0.0",
    "scope": {"project": "legacy shape", "mode": "STATIC"},
    "coverage": {"applicable": 1, "not_applicable": 1, "unknown": 0, "blocked": 0, "integrity_critical_unknown": 0},
    "findings": [],
    "blocked_checks": [],
    "release_recommendation": "PASS",
}


class ReportRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((ROOT / "examples/report.example.json").read_text(encoding="utf-8"))

    def test_json_preserves_canonical_finding_semantics(self):
        rendered = json.loads(render_json(self.report))
        self.assertEqual(rendered["findings"][0]["status"], "VERIFIED")
        self.assertEqual(rendered["findings"][0]["severity"], "MEDIUM")
        self.assertEqual(rendered["findings"][0]["resolution"], "FIXED")
        for key in ("status", "severity", "resolution"):
            self.assertEqual(rendered["findings"][0][key], self.report["findings"][0][key])
        self.assertEqual(rendered["release_recommendation"], self.report["release_recommendation"])

    def test_all_formats_redact_secret_key_values(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["api_key"] = "test-only-value"
        for rendered in (render_json(report), render_markdown(report), render_sarif(report), render_html(report)):
            self.assertNotIn("test-only-value", rendered)

    def test_common_token_patterns_are_redacted(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["evidence_chain"]["impact"]["statement"] = "Captured Bearer abcdefghijklmnopqrstuvwxyz123456"
        for rendered in (render_json(report), render_markdown(report), render_sarif(report), render_html(report)):
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz", rendered)

    def test_html_escapes_untrusted_markup(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["title"] = "<script>alert(1)</script>"
        output = render_html(report)
        self.assertNotIn("<script>alert(1)</script>", output)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", output)

    def test_markdown_escapes_inline_html(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["evidence_chain"]["impact"]["statement"] = "<img src=x onerror=alert(1)>"
        output = render_markdown(report)
        self.assertNotIn("<img src=x", output)
        self.assertIn("&lt;img", output)

    def test_sarif_uses_valid_envelope_and_location(self):
        report = copy.deepcopy(self.report)
        report["evidence"][0]["location"] = {"path": "next.config.ts", "start_line": 24}
        sarif = json.loads(render_sarif(report))
        self.assertEqual(sarif["version"], "2.1.0")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "SHX-F-GOS-HEADERS-001")
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "next.config.ts")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 24)

    def test_markdown_has_required_sections(self):
        markdown = render_markdown(self.report)
        for heading in (
            "## Scope",
            "## Coverage",
            "## Tools and evidence sources",
            "## Evidence",
            "## Findings",
            "## Rejected candidates",
            "## Blocked checks",
            "## Redaction summary",
        ):
            self.assertIn(heading, markdown)

    def test_report_title_prefers_project_and_falls_back_to_scope_id(self):
        self.assertIn(self.report["project"], render_markdown(self.report))
        anonymous = copy.deepcopy(self.report)
        anonymous.pop("project")
        markdown = render_markdown(anonymous)
        self.assertIn(f"# SecHelix security report — {self.report['scope_id']}", markdown)
        self.assertIn(self.report["scope_id"], render_html(anonymous))

    def test_html_is_standalone_and_script_free(self):
        output = render_html(self.report)
        self.assertTrue(output.startswith("<!doctype html>"))
        self.assertNotIn("<script", output.lower())

    def test_malformed_report_is_rejected(self):
        with self.assertRaises(ReportValidationError):
            render_json({"findings": []})

    def test_legacy_report_shape_is_rejected(self):
        for renderer in (render_json, render_markdown, render_sarif, render_html):
            with self.subTest(renderer=renderer.__name__):
                with self.assertRaises(ReportValidationError):
                    renderer(copy.deepcopy(LEGACY_REPORT))

    def test_lowercase_coverage_keys_are_rejected(self):
        report = copy.deepcopy(self.report)
        report["coverage"] = {"catalog_version": "2.2", "applicable": 41, "not_applicable": 496, "unknown": 8, "blocked": 1, "TOTAL": 546, "integrity_critical_unknown": 0}
        with self.assertRaises(ReportValidationError):
            render_json(report)

    def test_empty_coverage_is_rejected(self):
        report = copy.deepcopy(self.report)
        for key in ("APPLICABLE", "NOT_APPLICABLE", "UNKNOWN", "BLOCKED"):
            report["coverage"][key] = 0
        with self.assertRaises(ReportValidationError):
            render_json(report)

    def test_unknown_finding_status_is_rejected(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["status"] = "MAYBE"
        with self.assertRaises(ReportValidationError):
            render_json(report)


if __name__ == "__main__":
    unittest.main()
