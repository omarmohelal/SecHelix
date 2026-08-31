import copy
import json
import unittest
from pathlib import Path

from reports.report_renderer import ReportValidationError, render_html, render_json, render_markdown, render_sarif


ROOT = Path(__file__).resolve().parents[1]


class ReportRendererTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads((ROOT / "examples/report.example.json").read_text(encoding="utf-8"))

    def test_json_preserves_canonical_finding_semantics(self):
        rendered = json.loads(render_json(self.report))
        self.assertEqual(rendered["findings"][0]["status"], "VERIFIED")
        self.assertEqual(rendered["findings"][0]["severity"], "HIGH")
        self.assertEqual(rendered["findings"][0]["resolution"], "FIXED")

    def test_all_formats_redact_secret_key_values(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["api_key"] = "test-only-value"
        for rendered in (render_json(report), render_markdown(report), render_sarif(report), render_html(report)):
            self.assertNotIn("test-only-value", rendered)

    def test_common_token_patterns_are_redacted(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["impact"] = "Captured Bearer abcdefghijklmnopqrstuvwxyz123456"
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", render_json(report))

    def test_html_escapes_untrusted_markup(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["title"] = "<script>alert(1)</script>"
        output = render_html(report)
        self.assertNotIn("<script>alert(1)</script>", output)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", output)

    def test_markdown_escapes_inline_html(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["impact"] = "<img src=x onerror=alert(1)>"
        output = render_markdown(report)
        self.assertNotIn("<img src=x", output)
        self.assertIn("&lt;img", output)

    def test_sarif_uses_valid_envelope_and_location(self):
        sarif = json.loads(render_sarif(self.report))
        self.assertEqual(sarif["version"], "2.1.0")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["ruleId"], "SHX-AUTHZ-L02-DEMO")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 24)

    def test_markdown_has_required_sections(self):
        markdown = render_markdown(self.report)
        for heading in ("## Scope", "## Architecture", "## Coverage", "## Findings", "## Rejected candidates", "## Blocked checks"):
            self.assertIn(heading, markdown)

    def test_html_is_standalone_and_script_free(self):
        output = render_html(self.report)
        self.assertTrue(output.startswith("<!doctype html>"))
        self.assertNotIn("<script", output.lower())

    def test_malformed_report_is_rejected(self):
        with self.assertRaises(ReportValidationError):
            render_json({"findings": []})

    def test_unknown_finding_status_is_rejected(self):
        report = copy.deepcopy(self.report)
        report["findings"][0]["status"] = "MAYBE"
        with self.assertRaises(ReportValidationError):
            render_json(report)


if __name__ == "__main__":
    unittest.main()
