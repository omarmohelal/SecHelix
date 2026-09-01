"""Differential security review: does a change move the posture, and which way?"""

import unittest

from sechelix_core.diff_review import (
    NEW_RISK,
    RISK_REDUCED,
    UNCHANGED,
    UNKNOWN,
    classify_file,
    parse_unified_diff,
    review_diff,
    scoped_families,
)


def diff(path: str, added: list[str] = None, removed: list[str] = None) -> str:
    body = [f"diff --git a/{path} b/{path}", f"--- a/{path}", f"+++ b/{path}", "@@ -1,3 +1,4 @@"]
    body += [f"-{line}" for line in (removed or [])]
    body += [f"+{line}" for line in (added or [])]
    return "\n".join(body) + "\n"


class ParsingTests(unittest.TestCase):
    def test_parses_path_and_added_line_numbers(self):
        files = parse_unified_diff(diff("src/app.py", added=["x = 1", "y = 2"]))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].path, "src/app.py")
        self.assertEqual([n for n, _ in files[0].added], [1, 2])

    def test_unparseable_input_yields_no_files_rather_than_raising(self):
        self.assertEqual(parse_unified_diff("not a diff at all"), [])

    def test_binary_change_is_unknown_not_ignored(self):
        text = ("diff --git a/logo.png b/logo.png\n"
                "Binary files a/logo.png and b/logo.png differ\n")
        result = review_diff(text)
        self.assertEqual(result["overall"], UNKNOWN)
        self.assertEqual(result["deltas"][0]["kind"], "binary")


class DirectionTests(unittest.TestCase):
    def test_new_endpoint_is_new_risk(self):
        result = review_diff(diff("api/routes.py", added=["@app.get('/orders/<id>')"]))
        kinds = {d["kind"]: d["direction"] for d in result["deltas"]}
        self.assertEqual(kinds.get("route"), NEW_RISK)
        self.assertEqual(result["overall"], NEW_RISK)

    def test_removing_an_authorization_guard_is_new_risk(self):
        result = review_diff(diff("api/orders.py", removed=["    require_role('admin')"]))
        directions = [d for d in result["deltas"] if d["kind"] == "authorization_guard"]
        self.assertTrue(directions)
        self.assertEqual(directions[0]["direction"], NEW_RISK)
        self.assertEqual(result["overall"], NEW_RISK)

    def test_adding_an_authorization_guard_reduces_risk(self):
        result = review_diff(diff("api/orders.py", added=["    require_role('admin')"]))
        guard = [d for d in result["deltas"] if d["kind"] == "authorization_guard"][0]
        self.assertEqual(guard["direction"], RISK_REDUCED)

    def test_removing_a_security_header_is_new_risk(self):
        result = review_diff(diff("next.config.ts", removed=["  'Content-Security-Policy': csp,"]))
        header = [d for d in result["deltas"] if d["kind"] == "security_header"][0]
        self.assertEqual(header["direction"], NEW_RISK)

    def test_adding_a_security_header_reduces_risk(self):
        result = review_diff(diff("next.config.ts", added=["  'X-Frame-Options': 'DENY',"]))
        header = [d for d in result["deltas"] if d["kind"] == "security_header"][0]
        self.assertEqual(header["direction"], RISK_REDUCED)

    def test_dropping_an_rls_policy_is_new_risk(self):
        result = review_diff(diff("migrations/003.sql", removed=["DROP POLICY tenant_isolation ON orders;"]))
        rls = [d for d in result["deltas"] if d["kind"] == "rls_policy"][0]
        self.assertEqual(rls["direction"], NEW_RISK)

    def test_ci_privilege_increase_is_new_risk(self):
        result = review_diff(diff(".github/workflows/ci.yml", added=["    contents: write"]))
        ci = [d for d in result["deltas"] if d["kind"] == "ci_permission"][0]
        self.assertEqual(ci["direction"], NEW_RISK)

    def test_new_outbound_fetch_is_new_risk(self):
        result = review_diff(diff("lib/preview.py", added=["    return requests.get(url, timeout=2)"]))
        self.assertIn("outbound_fetch", {d["kind"] for d in result["deltas"]})

    def test_new_ai_tool_surface_is_new_risk(self):
        result = review_diff(diff("agent/loop.py", added=["    tools = {'delete_records': delete}"]))
        ai = [d for d in result["deltas"] if d["kind"] == "ai_tool"][0]
        self.assertEqual(ai["direction"], NEW_RISK)

    def test_authentication_change_is_unknown_when_added(self):
        result = review_diff(diff("auth/login.py", added=["    token = jwt.decode(raw, key)"]))
        auth = [d for d in result["deltas"] if d["kind"] == "authentication"][0]
        self.assertEqual(auth["direction"], UNKNOWN)


class SummaryTests(unittest.TestCase):
    def test_security_irrelevant_change_is_unchanged(self):
        result = review_diff(diff("README.md", added=["Fixed a typo in the introduction."]))
        self.assertEqual(result["overall"], UNCHANGED)
        self.assertEqual(result["deltas"], [])

    def test_new_risk_dominates_a_mixed_diff(self):
        text = (diff("a/routes.py", added=["@app.post('/admin/wipe')"])
                + diff("b/config.py", added=["  'X-Frame-Options': 'DENY',"]))
        result = review_diff(text)
        self.assertEqual(result["overall"], NEW_RISK)
        self.assertEqual(result["counts"][NEW_RISK] >= 1, True)
        self.assertEqual(result["counts"][RISK_REDUCED] >= 1, True)

    def test_every_delta_is_a_hypothesis_not_a_finding(self):
        result = review_diff(diff("api/routes.py", added=["@app.get('/x')"]))
        for delta in result["deltas"]:
            self.assertEqual(delta["claim_status"], "HYPOTHESIS")
            self.assertNotIn("severity", delta)

    def test_scoped_families_let_a_review_stay_narrow(self):
        result = review_diff(diff("db/queries.py", added=["    SELECT * FROM orders WHERE id = ?"]))
        families = scoped_families(result)
        self.assertIn("DB", families)
        self.assertNotIn("CRYPTO", families)

    def test_prose_files_do_not_trigger_code_shaped_rules(self):
        """Documentation describes code; it does not execute it."""
        result = review_diff(diff(
            "docs/auth.md",
            removed=["Review login, sessions, MFA and token refresh for fail-open states."],
        ))
        kinds = {d["kind"] for d in result["deltas"]}
        self.assertNotIn("authentication", kinds)
        self.assertEqual(result["overall"], UNCHANGED)

    def test_prose_files_still_report_a_leaked_secret(self):
        result = review_diff(diff("README.md", added=["api_key = sk-live-abc123"]))
        self.assertIn("secret", {d["kind"] for d in result["deltas"]})

    def test_counts_cover_every_delta(self):
        text = (diff("a.py", added=["@app.get('/a')"])
                + diff("b.py", removed=["require_role('admin')"])
                + diff("c.md", added=["docs only"]))
        result = review_diff(text)
        self.assertEqual(sum(result["counts"].values()), len(result["deltas"]))


if __name__ == "__main__":
    unittest.main()
