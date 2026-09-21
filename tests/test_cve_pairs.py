"""The paired real-CVE harness must be honest before it is useful.

A benchmark that scores itself is worth nothing, so these tests attack the ways this one could
flatter SecHelix: leaking which tree is vulnerable, accepting a finding that is merely near the
right place, letting an incomplete prediction set through, or reading silence as precision.
"""

import json
import tempfile
import unittest
from pathlib import Path

from evals import cve_pairs


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


CASE = {
    "id": "acme-idor",
    "cve": "CVE-2026-0001",
    "repo": "acme/widgets",
    "language": "python",
    "class": "broken access control",
    "vulnerable_commit": "a" * 40,
    "fix_commit": "b" * 40,
    "fix_files": ["app/orders.py"],
    "fix_lines": [[10, 14]],
    "accept_classes": ["idor", "broken access control", "authorization"],
    "scope": ["app"],
}


class CvePairHarnessTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.workdir = Path(self._tmp.name) / "work"
        raw = self.workdir / "raw" / CASE["id"]
        _write(raw / "v" / "app" / "orders.py",
               "\n" * 9 + "def get(order_id):\n    return db.find(order_id)\n")
        _write(raw / "f" / "app" / "orders.py",
               "\n" * 9 + "def get(order_id, tenant):\n    return db.find(order_id, tenant)\n")
        _write(raw / "v" / "CHANGELOG.md", "fixes CVE-2026-0001\n")
        _write(raw / "f" / "CHANGELOG.md", "fixes CVE-2026-0001\n")
        self.manifest = {"cases": [CASE]}

    def tearDown(self):
        self._tmp.cleanup()

    def prepare(self, seed=7):
        return cve_pairs.prepare(self.manifest, self.workdir, seed)

    def predictions(self, findings_by_export):
        path = self.workdir / "predictions.json"
        path.write_text(json.dumps({
            "model": "test", "runner": "unit test", "agent_host": "test",
            "limitations": ["synthetic"],
            "cases": [{"export_id": export, "findings": findings}
                      for export, findings in findings_by_export.items()],
        }), encoding="utf-8")
        return path

    def score(self, findings_by_export):
        output = self.workdir / "result.json"
        return cve_pairs.score(self.manifest, self.workdir,
                               self.predictions(findings_by_export), output)

    MATCH = {"file": "app/orders.py", "line": 11, "class": "IDOR",
             "claim": "order lookup is not scoped to the tenant"}

    # -- blinding ------------------------------------------------------------------

    def test_the_exported_tree_does_not_say_which_state_it_is(self):
        self.prepare()
        exported = sorted(p.name for p in (self.workdir / "blinded").iterdir())
        self.assertEqual(exported, ["case-01-a", "case-01-b"])
        for tree in (self.workdir / "blinded").iterdir():
            names = [p.name for p in tree.rglob("*")]
            self.assertNotIn("CHANGELOG.md", names)
            self.assertNotIn(".git", names)
            body = " ".join(p.read_text(encoding="utf-8") for p in tree.rglob("*") if p.is_file())
            self.assertNotIn("CVE-2026-0001", body)

    def test_the_reviewer_index_carries_no_ground_truth(self):
        self.prepare()
        index = (self.workdir / "cases-index.json").read_text(encoding="utf-8")
        for secret in ("acme-idor", "CVE-2026-0001", "vulnerable_letter", "orders.py"):
            self.assertNotIn(secret, index)

    def test_the_assignment_is_seeded_and_both_letters_occur(self):
        letters = set()
        for seed in range(12):
            key = self.prepare(seed)["key"][0]
            letters.add(key["vulnerable_letter"])
            self.assertEqual(self.prepare(seed)["key"][0]["vulnerable_letter"],
                             key["vulnerable_letter"])
        self.assertEqual(letters, {"a", "b"})

    # -- scoring -------------------------------------------------------------------

    def _exports(self, vulnerable_findings, patched_findings, seed=7):
        key = self.prepare(seed)["key"][0]
        other = "b" if key["vulnerable_letter"] == "a" else "a"
        return {f"case-01-{key['vulnerable_letter']}": vulnerable_findings,
                f"case-01-{other}": patched_findings}

    def test_found_in_vulnerable_and_silent_in_patched_is_a_pass(self):
        report = self.score(self._exports([self.MATCH], []))
        self.assertEqual(report["counts"]["PAIR_PASS"], 1)
        self.assertEqual(report["cases"][0]["outcome"], "PAIR_PASS")

    def test_claiming_it_in_both_states_is_not_a_pass(self):
        report = self.score(self._exports([self.MATCH], [dict(self.MATCH)]))
        self.assertEqual(report["cases"][0]["outcome"], "PAIR_PARTIAL")

    def test_missing_it_is_a_miss_even_with_plenty_of_other_findings(self):
        noise = [{"file": "app/orders.py", "line": 11, "class": "code smell",
                  "claim": "this function has no docstring"}]
        report = self.score(self._exports(noise, []))
        self.assertEqual(report["cases"][0]["outcome"], "PAIR_MISS")
        self.assertEqual(report["cases"][0]["other_findings_vulnerable"], 1)

    def test_the_right_class_in_the_wrong_file_does_not_count(self):
        elsewhere = [dict(self.MATCH, file="app/users.py")]
        self.assertEqual(self.score(self._exports(elsewhere, []))["cases"][0]["outcome"],
                         "PAIR_MISS")

    def test_the_right_file_far_from_the_fix_does_not_count(self):
        far = [dict(self.MATCH, line=500)]
        self.assertEqual(self.score(self._exports(far, []))["cases"][0]["outcome"], "PAIR_MISS")

    def test_the_right_place_with_an_unrelated_class_does_not_count(self):
        wrong_class = [{"file": "app/orders.py", "line": 11, "class": "hardcoded secret",
                        "claim": "a credential appears to be embedded here"}]
        self.assertEqual(self.score(self._exports(wrong_class, []))["cases"][0]["outcome"],
                         "PAIR_MISS")

    # -- what the result may claim --------------------------------------------------

    def test_an_incomplete_prediction_set_is_refused(self):
        self.prepare()
        with self.assertRaises(SystemExit):
            cve_pairs.score(self.manifest, self.workdir,
                            self.predictions({"case-01-a": []}), self.workdir / "r.json")

    def test_precision_is_never_computed_from_these_runs(self):
        report = self.score(self._exports([self.MATCH], []))
        for field in ("precision", "false_positive_rate", "applicability_accuracy",
                      "release_gate_accuracy"):
            self.assertEqual(report[field], "NOT_MEASURED")

    def test_rates_are_reported_with_their_denominator(self):
        report = self.score(self._exports([self.MATCH], []))
        self.assertEqual(report["pair_pass_rate"], "1/1")
        self.assertTrue(report["limitations"])
        self.assertEqual(len(report["predictions_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
