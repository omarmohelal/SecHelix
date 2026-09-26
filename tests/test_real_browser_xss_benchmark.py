import unittest
import urllib.parse
from types import SimpleNamespace

from evals.real_browser_xss_benchmark import (
    BLOCKED_BY_ENVIRONMENT,
    MEASURED,
    run_real_browser_xss_benchmark,
)
from sechelix_runner.pentest.browser import BrowserUnavailable


class FakeBrowser:
    def __init__(self, scope, *, interaction_policy, gateway):
        self.scope = scope
        self.interaction_policy = interaction_policy
        self.gateway = gateway
        self.url = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def navigate(self, url, *, timeout_ms):
        self.url = url
        return SimpleNamespace(
            status=200,
            url=url.split("?", 1)[0] + "?q=[REDACTED]",
            challenge=SimpleNamespace(value="NONE"),
            blocked_requests=0,
        )

    def window_marker_matches(self, name, expected):
        return urllib.parse.urlsplit(self.url).path == "/vulnerable"

    def text(self, selector, *, timeout_ms):
        if urllib.parse.urlsplit(self.url).path == "/clean":
            return "SECHELIX_XSS_MARKER_1"
        return ""


class MissingBrowser:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        raise BrowserUnavailable("fixture browser runtime missing")

    def __exit__(self, exc_type, exc, tb):
        return None


class RealBrowserXssBenchmarkTests(unittest.TestCase):
    def test_pair_is_measured_when_browser_backend_distinguishes_both_cases(self):
        result = run_real_browser_xss_benchmark(
            browser_factory=FakeBrowser,
            sechelix_commit="TEST-COMMIT",
        )
        self.assertEqual(result["measurement_status"], MEASURED)
        self.assertEqual(result["result_kind"], "REAL_BROWSER_XSS_INTEGRATION_BENCHMARK")
        self.assertEqual(result["case_count"], 2)
        self.assertEqual(result["sechelix_commit"], "TEST-COMMIT")
        self.assertTrue(all(case["matched"] for case in result["cases"]))
        self.assertEqual(
            {case["observed_behavior"] for case in result["cases"]},
            {"VULNERABLE_BEHAVIOR", "SECURE_BEHAVIOR"},
        )
        self.assertEqual(result["execution_mode"], "LOCAL")
        self.assertEqual(result["network_scope"], "literal-loopback-only")

    def test_missing_browser_is_blocked_by_environment_not_misreported(self):
        result = run_real_browser_xss_benchmark(browser_factory=MissingBrowser)
        self.assertEqual(result["measurement_status"], BLOCKED_BY_ENVIRONMENT)
        self.assertEqual(result["case_count"], 2)
        self.assertTrue(
            all(case["observed_behavior"] == "BLOCKED" for case in result["cases"])
        )
        self.assertTrue(all(case["blocker"] for case in result["cases"]))

    def test_artifact_contains_no_raw_injected_script(self):
        result = run_real_browser_xss_benchmark(browser_factory=FakeBrowser)
        rendered = str(result)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("__SECHELIX_XSS_MARKER", rendered)


if __name__ == "__main__":
    unittest.main()
