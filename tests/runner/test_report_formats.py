"""Report renderer tests.

The property under test throughout: **an empty report must not read as a clean
report.** A run where every lane was blocked produces no findings, and so does a
run of genuinely clean code. Every format has to distinguish them.
"""

import json
import unittest

from sechelix_runner.report import RENDERERS, to_html, to_markdown, to_sarif

INCOMPLETE_RUN = {
    "run_id": "RUN-TEST",
    "runner_version": "0.1.0",
    "target_commit": "abc123",
    "executor": "null",
    "started_at": "2026-09-02T00:00:00Z",
    "finished_at": "2026-09-02T00:01:00Z",
    "unsatisfied_mandatory": ["gate", "verify"],
    "records": {
        "map": {"role": "MAPPER", "status": "SUCCEEDED"},
        "authorization": {"role": "AUTHORIZATION", "status": "BLOCKED",
                          "blocker": "no reasoning executor configured"},
        "verify": {"role": "INDEPENDENT_VERIFIER", "status": "BLOCKED",
                   "blocker": "dependency not satisfied: authorization"},
        "gate": {"role": "RELEASE_GATE", "status": "BLOCKED",
                 "blocker": "dependency not satisfied: verify"},
    },
}

CLEAN_RUN = {
    **INCOMPLETE_RUN,
    "unsatisfied_mandatory": [],
    "records": {"map": {"role": "MAPPER", "status": "SUCCEEDED"}},
}


class SarifTests(unittest.TestCase):
    def test_is_sarif_210(self) -> None:
        self.assertEqual(to_sarif(INCOMPLETE_RUN)["version"], "2.1.0")

    def test_incomplete_run_is_not_an_empty_results_array(self) -> None:
        """An empty array in a code-scanning UI reads as "we looked and it was
        fine", which is the wrong message for a run that examined nothing."""
        results = to_sarif(INCOMPLETE_RUN)["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "sechelix/run-incomplete")
        self.assertEqual(results[0]["level"], "warning")

    def test_incomplete_message_names_the_nodes_and_disclaims(self) -> None:
        text = to_sarif(INCOMPLETE_RUN)["runs"][0]["results"][0]["message"]["text"]
        self.assertIn("gate", text)
        self.assertIn("verify", text)
        self.assertIn("No security claim can be made", text)

    def test_execution_successful_reflects_the_gate(self) -> None:
        self.assertFalse(to_sarif(INCOMPLETE_RUN)["runs"][0]["invocations"][0]["executionSuccessful"])
        self.assertTrue(to_sarif(CLEAN_RUN)["runs"][0]["invocations"][0]["executionSuccessful"])

    def test_a_complete_run_with_no_findings_has_no_results(self) -> None:
        self.assertEqual(to_sarif(CLEAN_RUN)["runs"][0]["results"], [])

    def test_findings_become_results_with_locations(self) -> None:
        run = {**CLEAN_RUN, "findings": [
            {"rule_id": "sechelix/idor", "title": "IDOR", "severity": "HIGH",
             "file": "app.py", "line": 42}]}
        result = to_sarif(run)["runs"][0]["results"][0]
        self.assertEqual(result["level"], "error")
        location = result["locations"][0]["physicalLocation"]
        self.assertEqual(location["artifactLocation"]["uri"], "app.py")
        self.assertEqual(location["region"]["startLine"], 42)

    def test_output_is_json_serialisable(self) -> None:
        json.dumps(to_sarif(INCOMPLETE_RUN))


class HtmlTests(unittest.TestCase):
    def test_incomplete_run_shows_a_banner_that_disclaims(self) -> None:
        page = to_html(INCOMPLETE_RUN)
        self.assertIn("INCOMPLETE", page)
        self.assertIn("not</em> a statement that the code is safe", page)

    def test_complete_run_says_so(self) -> None:
        self.assertIn("All mandatory nodes delivered", to_html(CLEAN_RUN))

    def test_page_is_self_contained(self) -> None:
        """A security report that pulls a stylesheet from a CDN phones home from
        whatever machine opens it."""
        page = to_html(INCOMPLETE_RUN)
        self.assertNotIn("<script", page)
        self.assertNotIn("http://", page.replace("http://www.w3.org", ""))
        self.assertNotIn("cdn.", page)

    def test_values_are_escaped(self) -> None:
        run = {**CLEAN_RUN, "run_id": "<img src=x onerror=alert(1)>"}
        page = to_html(run)
        self.assertNotIn("<img src=x", page)
        self.assertIn("&lt;img", page)


class MarkdownTests(unittest.TestCase):
    def test_incomplete_run_states_the_limitation(self) -> None:
        text = to_markdown(INCOMPLETE_RUN)
        self.assertIn("INCOMPLETE", text)
        self.assertIn("No security claim can be made", text)

    def test_every_node_appears_including_blocked_ones(self) -> None:
        text = to_markdown(INCOMPLETE_RUN)
        for node in INCOMPLETE_RUN["records"]:
            self.assertIn(node, text)


class RendererRegistryTests(unittest.TestCase):
    def test_all_four_formats_are_available(self) -> None:
        self.assertEqual(sorted(RENDERERS), ["html", "json", "markdown", "sarif"])

    def test_every_renderer_returns_a_non_empty_string(self) -> None:
        for name, render in RENDERERS.items():
            with self.subTest(format=name):
                self.assertTrue(render(INCOMPLETE_RUN).strip())


if __name__ == "__main__":
    unittest.main()
