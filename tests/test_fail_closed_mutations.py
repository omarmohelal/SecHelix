"""Mutation tests for the fail-closed properties this project's claims rest on.

Ordinary tests check that the good path works. These take a report that legitimately
passes and mutate exactly one thing that *should* stop it, then assert it stops.

The distinction matters because every fail-closed guarantee here is a negative
claim — "this can never pass" — and a negative claim is only tested by trying to
make it happen. A gate that returns PASS for a well-formed report tells you
nothing about whether it also returns PASS for a malformed one.

Each test names the property in its docstring. If one starts failing, the
corresponding public claim has become false and should be removed from the README
before the test is weakened.
"""

import copy
import json
import unittest
from pathlib import Path

import scripts.security_gate as gate
from sechelix_core.revision import assess_freshness, bind_report
from sechelix_core.untrusted_repo import resolve_trust_policy

ROOT = Path(__file__).resolve().parents[1]
REPORT = json.loads((ROOT / "examples/report.example.json").read_text(encoding="utf-8"))
POLICY = json.loads((ROOT / "policies/default.json").read_text(encoding="utf-8"))

COMMIT = "06ab8ca680d477b8005805d67ab44d11507e3321"
OTHER = "a7f1f4799234c5410c872a54de18f3dbbcc316cc"


def report():
    return copy.deepcopy(REPORT)


class BaselineTests(unittest.TestCase):
    """Without a passing baseline, every mutation below proves nothing."""

    def test_the_unmutated_report_passes(self):
        decision = gate.evaluate(report(), POLICY)
        self.assertEqual(decision.exit_code, 0, decision.reasons)


class InvalidReportCannotPass(unittest.TestCase):
    """An invalid report can never PASS."""

    def _assert_not_pass(self, mutated, label):
        try:
            decision = gate.evaluate(mutated, POLICY)
        except (gate.GateInputError, ValueError, KeyError, TypeError):
            return  # refusing to evaluate is a valid fail-closed outcome
        self.assertNotEqual(decision.exit_code, 0, f"{label} still returned PASS")

    def test_a_missing_required_block_cannot_pass(self):
        for field in ("coverage", "findings", "evidence", "scope_id", "mode"):
            with self.subTest(field=field):
                mutated = report()
                mutated.pop(field, None)
                self._assert_not_pass(mutated, f"report without {field}")

    def test_a_wrong_typed_findings_block_cannot_pass(self):
        for bad in ({}, "none", 0, None):
            with self.subTest(value=repr(bad)):
                mutated = report()
                mutated["findings"] = bad
                self._assert_not_pass(mutated, f"findings={bad!r}")

    def test_an_unknown_status_cannot_pass(self):
        mutated = report()
        if mutated["findings"]:
            mutated["findings"][0]["status"] = "PROBABLY_FINE"
            self._assert_not_pass(mutated, "invented status")

    def test_an_unknown_severity_cannot_pass(self):
        mutated = report()
        if mutated["findings"]:
            mutated["findings"][0]["severity"] = "SPICY"
            self._assert_not_pass(mutated, "invented severity")


class UnverifiedHighCannotRelease(unittest.TestCase):
    """An unverified High or Critical can never release as clean."""

    def _open_finding(self, severity, status):
        mutated = report()
        base = mutated["findings"][0] if mutated["findings"] else None
        if base is None:
            self.skipTest("example report has no findings to mutate")
        injected = copy.deepcopy(base)
        injected["finding_id"] = "SHX-F-MUTANT-1"
        injected["severity"] = severity
        injected["status"] = status
        injected["resolution"] = "OPEN"
        injected["verification"] = {
            "independent": False,
            "outcome": "NOT_RUN",
            "evidence_ids": [],
            "refutation_attempt": "none attempted",
        }
        injected["regression"] = {
            "status": "NOT_RUN",
            "command": "none",
            "assertion": "none",
            "evidence_ids": [],
        }
        mutated["findings"].append(injected)
        return mutated

    def test_an_open_unverified_critical_does_not_pass(self):
        decision = gate.evaluate(self._open_finding("CRITICAL", "HYPOTHESIS"), POLICY)
        self.assertNotEqual(decision.exit_code, 0, decision.reasons)

    def test_an_open_unverified_high_does_not_pass(self):
        decision = gate.evaluate(self._open_finding("HIGH", "HYPOTHESIS"), POLICY)
        self.assertNotEqual(decision.exit_code, 0, decision.reasons)

    def test_likely_but_unproven_high_does_not_pass(self):
        """The tempting case: plausible, unproven, and still not releasable."""
        decision = gate.evaluate(self._open_finding("HIGH", "LIKELY_BUT_UNPROVEN"), POLICY)
        self.assertNotEqual(decision.exit_code, 0, decision.reasons)

    def test_declaring_a_recommendation_does_not_override_the_gate(self):
        """A report cannot talk its way past evaluation."""
        mutated = self._open_finding("CRITICAL", "HYPOTHESIS")
        mutated["release_recommendation"] = "PASS"
        decision = gate.evaluate(mutated, POLICY)
        self.assertNotEqual(decision.exit_code, 0, decision.reasons)


class StaleReportCannotPass(unittest.TestCase):
    """A report bound to one revision can never be usable against another."""

    def _bound(self, commit, **kw):
        return bind_report(report(), repository="omarmohelal/example", commit=commit, **kw)

    def test_a_different_commit_is_not_usable(self):
        verdict = assess_freshness(self._bound(COMMIT), current_commit=OTHER)
        self.assertFalse(verdict.usable)

    def test_a_dirty_report_tree_is_not_usable(self):
        verdict = assess_freshness(
            self._bound(COMMIT, working_tree="DIRTY", dirty_paths=["a.py"]),
            current_commit=COMMIT,
        )
        self.assertFalse(verdict.usable)

    def test_a_dirty_current_tree_is_not_usable(self):
        verdict = assess_freshness(
            self._bound(COMMIT), current_commit=COMMIT, current_working_tree="DIRTY")
        self.assertFalse(verdict.usable)

    def test_stripping_the_revision_does_not_make_it_fresh(self):
        """Deleting the binding must yield UNKNOWN, never FRESH."""
        mutated = self._bound(COMMIT)
        del mutated["target_revision"]
        verdict = assess_freshness(mutated, current_commit=COMMIT)
        self.assertFalse(verdict.usable)

    def test_a_degenerate_current_commit_is_never_fresh(self):
        """An empty commit is what a failed `git rev-parse` returns, not a match."""
        for degenerate in ("", " ", "0", "06", "06ab", chr(10), chr(9)):
            with self.subTest(repr(degenerate)):
                verdict = assess_freshness(self._bound(COMMIT), current_commit=degenerate)
                self.assertFalse(verdict.usable, degenerate)
                self.assertNotEqual(verdict.state, "FRESH")

    def test_a_degenerate_report_commit_is_never_fresh(self):
        from sechelix_core.revision import RevisionError

        # bind_report refuses a non-hex commit outright; a short hex one must
        # still fail the comparison rather than matching everything.
        verdict = assess_freshness(self._bound("06ab"), current_commit=COMMIT)
        self.assertFalse(verdict.usable)
        with self.assertRaises(RevisionError):
            self._bound("not-hex")

    def test_only_an_exact_prefix_match_is_fresh(self):
        for wrong in (OTHER, OTHER[:12], COMMIT[:11] + "f"):
            with self.subTest(wrong):
                self.assertFalse(assess_freshness(self._bound(COMMIT),
                                                  current_commit=wrong).usable)


class RepositoryContentCannotChangePolicy(unittest.TestCase):
    """Nothing inside a reviewed repository can widen its own trust policy."""

    def _scope(self, **trust):
        from sechelix_core.untrusted_repo import default_untrusted_scope

        scope = default_untrusted_scope("SCOPE-MUT-1", "target-project", ["TGT-1"])
        scope["trust"].update(trust)
        return scope

    def test_the_default_scope_grants_nothing(self):
        policy = resolve_trust_policy(self._scope())
        self.assertEqual(policy.repository_content, "DATA_ONLY")
        self.assertEqual(policy.promoted_paths, frozenset())
        self.assertEqual(policy.enabled_capabilities, frozenset())
        # Deny-by-default: every capability, and anything not in the vocabulary.
        for capability in ("FILESYSTEM_WRITE", "NETWORK", "PACKAGE_INSTALL",
                           "EXTERNAL_MCP", "HOOKS", "BECOME_ROOT"):
            self.assertFalse(policy.allows(capability), capability)

    def test_a_wildcard_promotion_is_refused(self):
        for hostile in ("*", "**", ".", "./", "**/*"):
            with self.subTest(hostile):
                with self.assertRaises(Exception):
                    resolve_trust_policy(self._scope(promoted_control_sources=[hostile]))

    def test_an_unknown_capability_is_refused(self):
        with self.assertRaises(Exception):
            resolve_trust_policy(self._scope(capability_escalations=["BECOME_ROOT"]))

    def test_a_missing_trust_block_is_refused_not_defaulted(self):
        scope = self._scope()
        del scope["trust"]
        with self.assertRaises(Exception):
            resolve_trust_policy(scope)

    def test_promoting_repository_content_to_control_is_explicit(self):
        """DATA_ONLY must never be reachable by omission or by a typo."""
        scope = self._scope(repository_content="TRUSTED_CONTROLL")  # deliberate typo
        with self.assertRaises(Exception):
            resolve_trust_policy(scope)


class PatchPathsCannotEscape(unittest.TestCase):
    """A finding id from an untrusted report can never become an arbitrary path."""

    def test_traversal_and_devices_are_refused(self):
        from sechelix_core.patch_mode import PatchModeError, propose

        finding = {
            "finding_id": "PLACEHOLDER",
            "title": "t",
            "status": "VERIFIED",
            "severity": "HIGH",
            "affected_surface": ["a.py:1"],
            "verification": {"independent": True, "outcome": "VERIFIED",
                             "evidence_ids": [], "refutation_attempt": "x"},
            "remediation": {"root_cause_fix": "x", "evidence_ids": []},
            "regression": {"status": "NOT_RUN", "command": "x",
                           "assertion": "x", "evidence_ids": []},
        }
        hostile = ["../../etc/passwd", "..", "a/b", "/abs", "NUL", "CON.patch",
                   "x.", "C:evil", "a\\b"]
        for fid in hostile:
            with self.subTest(fid):
                mutated = dict(finding, finding_id=fid)
                with self.assertRaises(PatchModeError):
                    propose([mutated])

    def test_every_written_path_stays_under_the_output_directory(self):
        from sechelix_core.patch_mode import propose, write_patch_set

        finding = {
            "finding_id": "SHX-F-1", "title": "t", "status": "VERIFIED",
            "severity": "HIGH", "affected_surface": ["a.py:1"],
            "verification": {"independent": True, "outcome": "VERIFIED",
                             "evidence_ids": [], "refutation_attempt": "x"},
            "remediation": {"root_cause_fix": "x", "evidence_ids": []},
            "regression": {"status": "NOT_RUN", "command": "x",
                           "assertion": "x", "evidence_ids": []},
        }
        written = {}
        patch_set = propose([finding], diffs={"SHX-F-1": "--- a\n+++ b\n"},
                            output_dir="work/out")
        write_patch_set(patch_set, "work/out", writer=lambda p, c: written.__setitem__(p, c))
        self.assertTrue(written)
        for path in written:
            self.assertTrue(path.startswith("work/out/"), path)
            self.assertNotIn("..", path)


if __name__ == "__main__":
    unittest.main()
