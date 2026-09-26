import unittest

from evals.real_browser_session_benchmark import (
    BLOCKED_BY_ENVIRONMENT,
    MEASURED,
    run_real_browser_session_benchmark,
)
from sechelix_runner.pentest.browser import (
    BrowserChallenge,
    BrowserUnavailable,
    LoginResult,
)


class FakeSessionBrowser:
    def __init__(
        self,
        scope,
        *,
        access,
        interaction_policy,
        gateway,
        authentication_context,
    ):
        self.scope = scope
        self.access = access
        self.interaction_policy = interaction_policy
        self.gateway = gateway
        self.authentication_context = authentication_context

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def verify_session(self, probe):
        cookie_value = str(self.access.cookies[0]["value"])
        verified = cookie_value == "fixture-session-valid"
        return LoginResult(
            profile_name=self.access.profile_name,
            role=self.access.role,
            verified=verified,
            url=probe.url,
            challenge=BrowserChallenge.NONE,
            reason="test fixture",
        )


class MissingSessionBrowser:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        raise BrowserUnavailable("chromium not installed")

    def __exit__(self, exc_type, exc, tb):
        return None


class RealBrowserSessionBenchmarkTests(unittest.TestCase):
    def test_valid_and_invalid_sessions_are_isolated(self):
        result = run_real_browser_session_benchmark(
            browser_factory=FakeSessionBrowser,
            sechelix_commit="TEST-COMMIT",
        )
        self.assertEqual(result["measurement_status"], MEASURED)
        self.assertEqual(
            result["result_kind"],
            "REAL_BROWSER_SESSION_INTEGRATION_BENCHMARK",
        )
        self.assertEqual(result["case_count"], 2)
        self.assertTrue(all(case["matched"] for case in result["cases"]))
        by_id = {case["case_id"]: case for case in result["cases"]}
        self.assertTrue(by_id["SESSION-REAL-VALID"]["observed_verified"])
        self.assertFalse(by_id["SESSION-REAL-INVALID"]["observed_verified"])
        self.assertFalse(result["credential_material_persisted"])
        self.assertFalse(result["is_full_sechelix_workflow"])

    def test_missing_browser_is_blocked_by_environment(self):
        result = run_real_browser_session_benchmark(
            browser_factory=MissingSessionBrowser
        )
        self.assertEqual(result["measurement_status"], BLOCKED_BY_ENVIRONMENT)
        self.assertEqual(result["case_count"], 2)
        self.assertTrue(all(case["observed_verified"] is None for case in result["cases"]))
        self.assertTrue(all(case["blocker"] for case in result["cases"]))

    def test_session_values_never_enter_artifact(self):
        result = run_real_browser_session_benchmark(
            browser_factory=FakeSessionBrowser
        )
        rendered = str(result)
        self.assertNotIn("fixture-session-valid", rendered)
        self.assertNotIn("fixture-session-invalid", rendered)
        self.assertNotIn('"Cookie"', rendered)
        self.assertEqual(result["network_scope"], "literal-loopback-only")


if __name__ == "__main__":
    unittest.main()
