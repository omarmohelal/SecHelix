"""Patch mode must propose only what was proven, and must never apply anything."""

import unittest

from sechelix_core.patch_mode import (
    PatchModeError,
    build_rationale,
    propose,
    write_patch_set,
)

DIFF = """--- a/app/reports.py
+++ b/app/reports.py
@@
-    report = db.get(report_id)
+    report = db.get(report_id, tenant_id=session.tenant_id)
"""


def finding(fid="SHX-F-1", status="VERIFIED", **extra):
    base = {
        "finding_id": fid,
        "title": "Report lookup omits the tenant predicate",
        "status": status,
        "severity": "HIGH",
        "confidence": "HIGH",
        "affected_surface": ["app/reports.py:41"],
        "evidence_chain": {
            "reachability": {"statement": "The route is reachable by any authenticated tenant."},
            "impact": {"statement": "Another tenant's report is returned in full."},
        },
        "verification": {
            "independent": True,
            "outcome": "VERIFIED",
            "evidence_ids": ["EV-001"],
            "refutation_attempt": "Checked for a row-level policy on the table; none is enabled.",
        },
        "remediation": {
            "root_cause_fix": "Scope the lookup by the session tenant.",
            "evidence_ids": ["EV-001"],
        },
        "regression": {
            "status": "NOT_RUN",
            "command": "pytest tests/test_reports.py::test_cross_tenant_denied",
            "assertion": "A tenant B session requesting a tenant A report receives 404.",
            "evidence_ids": ["EV-001"],
        },
        "resolution": "OPEN",
    }
    base.update(extra)
    return base


class GatingTests(unittest.TestCase):
    def test_a_verified_finding_is_proposed(self):
        result = propose([finding()], diffs={"SHX-F-1": DIFF})
        self.assertEqual(len(result.proposals), 1)
        self.assertEqual(result.proposals[0].patch_path, "work/patches/SHX-F-1.patch")

    def test_an_unverified_finding_is_refused_with_a_reason(self):
        result = propose([finding(status="HYPOTHESIS")])
        self.assertEqual(result.proposals, [])
        self.assertEqual(len(result.refusals), 1)
        self.assertIn("unverified", result.refusals[0].reason)

    def test_a_refuted_finding_is_refused(self):
        result = propose([finding(status="FALSE_POSITIVE")])
        self.assertIn("nothing to fix", result.refusals[0].reason)

    def test_likely_but_unproven_is_not_patchable(self):
        """The most tempting case: plausible, and still not proven."""
        result = propose([finding(status="LIKELY_BUT_UNPROVEN")])
        self.assertEqual(result.proposals, [])

    def test_a_duplicate_is_redirected_to_its_primary(self):
        result = propose([finding(status="DUPLICATE_ROOT_CAUSE")])
        self.assertIn("primary finding", result.refusals[0].reason)

    def test_every_status_is_either_proposed_or_refused(self):
        statuses = ["VERIFIED", "HYPOTHESIS", "LIKELY_BUT_UNPROVEN",
                    "FALSE_POSITIVE", "DUPLICATE_ROOT_CAUSE", "BLOCKED_BY_ENVIRONMENT"]
        findings = [finding(f"SHX-F-{i}", status=s) for i, s in enumerate(statuses)]
        result = propose(findings)
        self.assertEqual(len(result.proposals) + len(result.refusals), len(statuses))


class HonestyTests(unittest.TestCase):
    def test_a_proposal_is_never_marked_applied(self):
        payload = propose([finding()], diffs={"SHX-F-1": DIFF}).as_dict()
        self.assertFalse(payload["proposals"][0]["applied"])
        self.assertEqual(payload["proposals"][0]["application_method"], "MANUAL_REVIEW_REQUIRED")

    def test_regression_status_is_not_upgraded(self):
        """A patch does not become a fix because a patch exists."""
        proposal = propose([finding()], diffs={"SHX-F-1": DIFF}).proposals[0]
        self.assertEqual(proposal.regression_status, "NOT_RUN")

    def test_a_missing_regression_block_defaults_to_not_run(self):
        f = finding()
        del f["regression"]
        self.assertEqual(propose([f]).proposals[0].regression_status, "NOT_RUN")

    def test_the_rationale_states_what_the_patch_does_not_cover(self):
        rationale, scope = build_rationale(finding(), diff=DIFF)
        self.assertIn("does not cover", rationale)
        self.assertIn("not covered", scope)

    def test_the_rationale_carries_the_evidence_chain(self):
        rationale, _ = build_rationale(finding(), diff=DIFF)
        self.assertIn("reachable by any authenticated tenant", rationale)
        self.assertIn("refutation", rationale.lower())

    def test_a_missing_diff_is_stated_not_invented(self):
        rationale, _ = build_rationale(finding(), diff="")
        self.assertIn("no diff was supplied", rationale)


class SafetyTests(unittest.TestCase):
    def test_a_traversing_finding_id_is_refused(self):
        """A report can come from an untrusted repository; ids reach a write path."""
        for hostile in ["../../.ssh/authorized_keys", "..", "a/b", "/etc/passwd", ""]:
            with self.subTest(hostile):
                f = finding(fid=hostile)
                if not hostile:
                    self.assertEqual(propose([f]).proposals, [])
                    continue
                with self.assertRaises(PatchModeError):
                    propose([f])

    def test_writing_touches_only_the_output_directory(self):
        written: dict[str, str] = {}
        patch_set = propose([finding()], diffs={"SHX-F-1": DIFF}, output_dir="work/out")
        paths = write_patch_set(patch_set, "work/out",
                                writer=lambda p, c: written.__setitem__(p, c))
        self.assertEqual(sorted(paths), ["work/out/SHX-F-1.md", "work/out/SHX-F-1.patch"])
        for path in written:
            self.assertTrue(path.startswith("work/out/"), path)

    def test_a_refused_finding_writes_nothing(self):
        written: dict[str, str] = {}
        patch_set = propose([finding(status="HYPOTHESIS")])
        write_patch_set(patch_set, "work/out", writer=lambda p, c: written.__setitem__(p, c))
        self.assertEqual(written, {})


if __name__ == "__main__":
    unittest.main()
