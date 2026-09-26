import unittest
import urllib.parse

import evals.real_browser_session_revocation_benchmark as bench
from sechelix_runner.pentest.browser import (
    BrowserChallenge,
    BrowserUnavailable,
    LoginResult,
)


class FakeRevocationBrowser:
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

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return None

    def verify_session(self, probe):
        path = urllib.parse.urlsplit(probe.url).path
        cookie_ok = self.access.cookies[0]["value"] == "fixture-session-valid"
        if path == "/clean":
            verified = cookie_ok and bench._Handler.clean_active
        else:
            verified = cookie_ok
        return LoginResult(
            profile_name=self.access.profile_name,
            role=self.access.role,
            verified=verified,
            url=probe.url,
            challenge=BrowserChallenge.NONE,
            reason="test fixture",
        )


class MissingRevocationBrowser:
    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        raise BrowserUnavailable("playwright missing")

    def __exit__(self, exc_type, exc, tb):
        return None


class RealBrowserSessionRevocationBenchmarkTests(unittest.TestCase):
    def test_vulnerable_and_clean_revocation_paths_are_distinguished(self):
        result = bench.run_real_browser_session_revocation_benchmark(
            browser_factory=FakeRevocationBrowser,
            sechelix_commit="TEST-COMMIT",
        )
        self.assertEqual(result["measurement_status"], bench.MEASURED)
        self.assertEqual(
            result["result_kind"],
            "REAL_BROWSER_SESSION_REVOCATION_INTEGRATION_BENCHMARK",
        )
        self.assertEqual(result["case_count"], 2)
        self.assertTrue(all(case["control_verified"] for case in result["cases"]))
        self.assertTrue(all(case["matched"] for case in result["cases"]))
        by_id = {case["case_id"]: case for case in result["cases"]}
        self.assertTrue(
            by_id["SESSION-REVOCATION-REAL-VULNERABLE"][
                "observed_post_revocation_verified"
            ]
        )
        self.assertFalse(
            by_id["SESSION-REVOCATION-REAL-CLEAN"][
                "observed_post_revocation_verified"
            ]
        )

    def test_missing_browser_is_blocked_by_environment(self):
        result = bench.run_real_browser_session_revocation_benchmark(
            browser_factory=MissingRevocationBrowser
        )
        self.assertEqual(result["measurement_status"], bench.BLOCKED_BY_ENVIRONMENT)
        self.assertEqual(result["case_count"], 2)
        self.assertTrue(all(case["control_verified"] is None for case in result["cases"]))
        self.assertTrue(all(case["blocker"] for case in result["cases"]))

    def test_session_secret_never_enters_result(self):
        result = bench.run_real_browser_session_revocation_benchmark(
            browser_factory=FakeRevocationBrowser
        )
        rendered = str(result)
        self.assertNotIn("fixture-session-valid", rendered)
        self.assertNotIn('"Cookie"', rendered)
        self.assertFalse(result["credential_material_persisted"])
        self.assertFalse(result["is_full_sechelix_workflow"])


if __name__ == "__main__":
    unittest.main()
