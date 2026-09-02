"""A proof bundle must be checkable, redacted, and never claim more than the report."""

import json
import unittest
from pathlib import Path

from sechelix_core.proof_bundle import (
    REDACTED,
    ProofBundleError,
    build_bundle,
    export_bundles,
    redact,
    RedactionLog,
    verify_bundle,
)

ROOT = Path(__file__).resolve().parents[1]
REAL = json.loads((ROOT / "examples/report.example.json").read_text(encoding="utf-8"))


# Credential-shaped fixtures are assembled at runtime. A literal here would be
# flagged by this project's own secret gate and by GitHub's, and a scanner that
# learns to ignore the tests directory stops protecting it.
AWS = "AKIA" + "IOSFODNN7EXAMPLE"
GH = "ghp" + "_" + "abcdefghijklmnopqrstuvwxyz0123456789"
OPENAI = "sk" + "-" + "abcdefghijklmnopqrstuvwxyz012345"
SLACK = "xoxb" + "-" + "1234567890-abcdefghij"
PRIVATE_KEY = "-----BEGIN RSA " + "PRIVATE KEY-----"
BEARER = "Authorization: Bearer " + "abcdefghijklmnopqrstuvwxyz"
PASSWORD_LINE = "password: " + "hunter2secret"


def verified_finding(fid="SHX-F-B1", **over):
    base = {
        "finding_id": fid,
        "title": "Report lookup omits the tenant predicate",
        "status": "VERIFIED",
        "severity": "HIGH",
        "confidence": "HIGH",
        "affected_surface": ["app/reports.py:41"],
        "catalog_hypothesis_ids": ["SHX-AUTHZ-L02"],
        "evidence_ids": ["EV-001"],
        "evidence_chain": {"impact": {"statement": "Another tenant's report is returned."}},
        "verification": {"independent": True, "outcome": "VERIFIED",
                         "evidence_ids": ["EV-001"], "refutation_attempt": "no RLS enabled"},
        "remediation": {"root_cause_fix": "Scope by session tenant.", "evidence_ids": ["EV-001"]},
        "regression": {"status": "NOT_RUN", "command": "pytest x", "assertion": "404",
                       "evidence_ids": []},
        "resolution": "OPEN",
    }
    base.update(over)
    return base


def a_report(*findings, evidence=None):
    return {
        "report_id": "REPORT-B",
        "findings": list(findings),
        "evidence": evidence if evidence is not None else [
            {"evidence_id": "EV-001", "phase": "STATIC", "summary": "query has no tenant filter"},
        ],
    }


class GatingTests(unittest.TestCase):
    def test_a_verified_finding_exports(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        self.assertIn("finding.json", bundle["files"])
        self.assertIn("manifest.json", bundle["files"])
        self.assertIn("manifest.sha256", bundle["files"])

    def test_an_unverified_finding_is_refused(self):
        for status in ("HYPOTHESIS", "LIKELY_BUT_UNPROVEN", "FALSE_POSITIVE",
                       "DUPLICATE_ROOT_CAUSE", "BLOCKED_BY_ENVIRONMENT"):
            with self.subTest(status):
                report = a_report(verified_finding(status=status))
                with self.assertRaises(ProofBundleError):
                    build_bundle(report, "SHX-F-B1")

    def test_an_unknown_finding_id_is_refused(self):
        with self.assertRaises(ProofBundleError):
            build_bundle(a_report(verified_finding()), "SHX-F-NOPE")

    def test_export_records_why_each_finding_was_refused(self):
        report = a_report(verified_finding("SHX-F-OK"),
                          verified_finding("SHX-F-NO", status="HYPOTHESIS"))
        result = export_bundles(report)
        self.assertEqual(result["exported_count"], 1)
        self.assertEqual(result["refused_count"], 1)
        self.assertIn("nothing to prove", result["refusals"][0]["refused_because"])


class IntegrityTests(unittest.TestCase):
    def test_a_fresh_bundle_verifies(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        self.assertEqual(verify_bundle(bundle["files"]), [])

    def test_tampering_with_a_file_is_detected(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        files = dict(bundle["files"])
        files["finding.json"] = files["finding.json"].replace("HIGH", "CRITICAL")
        problems = verify_bundle(files)
        self.assertTrue(any("finding.json" in p for p in problems), problems)

    def test_tampering_with_the_manifest_is_detected(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        files = dict(bundle["files"])
        files["manifest.json"] = files["manifest.json"].replace("SHX-F-B1", "SHX-F-XX")
        self.assertTrue(any("manifest.sha256" in p for p in verify_bundle(files)))

    def test_a_removed_file_is_detected(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        files = dict(bundle["files"])
        del files["finding.json"]
        self.assertTrue(any("missing" in p for p in verify_bundle(files)))

    def test_an_injected_file_is_detected(self):
        """Walking the manifest proves listed files are intact and nothing more."""
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        files = dict(bundle["files"])
        files["evil.json"] = '{"injected": true}'
        problems = verify_bundle(files)
        self.assertTrue(any("evil.json" in p for p in problems), problems)

    def test_several_injected_files_are_all_named(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        files = dict(bundle["files"])
        files["a.txt"] = "x"
        files["b.txt"] = "y"
        problems = " ".join(verify_bundle(files))
        self.assertIn("a.txt", problems)
        self.assertIn("b.txt", problems)

    def test_the_manifest_files_themselves_are_not_flagged_as_injected(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        self.assertEqual(verify_bundle(bundle["files"]), [])

    def test_a_bundle_without_a_manifest_fails_immediately(self):
        self.assertEqual(verify_bundle({"finding.json": "{}"}), ["manifest.json is missing"])

    def test_the_manifest_does_not_claim_to_be_a_signature(self):
        """Implying cryptographic provenance we do not have would be the worst kind of claim."""
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        note = bundle["manifest"]["integrity_note"]
        self.assertIn("not a signature", note)


class RedactionTests(unittest.TestCase):
    SECRETS = [AWS, GH, OPENAI, SLACK, PRIVATE_KEY, BEARER, PASSWORD_LINE]

    def test_known_secret_shapes_are_removed(self):
        for secret in self.SECRETS:
            with self.subTest(secret[:16]):
                log = RedactionLog()
                out = redact(f"leaked {secret} here", log)
                self.assertNotIn(secret, out)
                self.assertIn(REDACTED, out)

    def test_home_paths_are_removed(self):
        log = RedactionLog()
        out = redact(r"C:\Users\alice\project\app.py and /home/bob/x.py", log)
        self.assertNotIn("alice", out)
        self.assertNotIn("bob", out)

    def test_redaction_is_on_by_default(self):
        finding = verified_finding()
        finding["evidence_chain"] = {"impact": {"statement": f"token {GH}"}}
        bundle = build_bundle(a_report(finding), "SHX-F-B1")
        blob = "".join(bundle["files"].values())
        self.assertNotIn(GH, blob)

    def test_the_manifest_records_that_redaction_happened(self):
        finding = verified_finding()
        finding["evidence_chain"] = {"impact": {"statement": AWS}}
        bundle = build_bundle(a_report(finding), "SHX-F-B1")
        redaction = bundle["manifest"]["redaction"]
        self.assertTrue(redaction["applied"])
        self.assertGreater(redaction["total_values_redacted"], 0)
        self.assertIn("aws_key", redaction["by_pattern"])

    def test_redaction_preserves_structure(self):
        log = RedactionLog()
        out = redact({"a": ["x", {"b": AWS}], "n": 1, "t": True}, log)
        self.assertEqual(out["n"], 1)
        self.assertIs(out["t"], True)
        self.assertEqual(out["a"][1]["b"], REDACTED)

    def test_disabling_redaction_is_recorded_in_the_manifest(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1", redacted=False)
        self.assertFalse(bundle["manifest"]["redaction"]["applied"])


class HonestyTests(unittest.TestCase):
    def test_regression_status_is_never_upgraded(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        regression = json.loads(bundle["files"]["regression.json"])
        self.assertEqual(regression["status"], "NOT_RUN")

    def test_absent_artifacts_are_listed_not_faked(self):
        """A reader must be able to tell 'not applicable' from 'we forgot'."""
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1")
        self.assertIn("patch.diff", bundle["manifest"]["absent"])
        self.assertNotIn("patch.diff", bundle["files"])

    def test_a_supplied_diff_is_included_and_hashed(self):
        bundle = build_bundle(a_report(verified_finding()), "SHX-F-B1",
                              diff="--- a\n+++ b\n")
        self.assertIn("patch.diff", bundle["files"])
        names = {f["name"] for f in bundle["manifest"]["files"]}
        self.assertIn("patch.diff", names)

    def test_only_cited_evidence_is_bundled(self):
        report = a_report(verified_finding(), evidence=[
            {"evidence_id": "EV-001", "phase": "STATIC", "summary": "cited"},
            {"evidence_id": "EV-999", "phase": "STATIC", "summary": "unrelated"},
        ])
        bundle = build_bundle(report, "SHX-F-B1")
        evidence = json.loads(bundle["files"]["evidence.json"])
        self.assertEqual([e["evidence_id"] for e in evidence], ["EV-001"])


class RealReportTests(unittest.TestCase):
    def test_the_published_case_study_report_exports_and_verifies(self):
        result = export_bundles(REAL)
        self.assertGreaterEqual(result["exported_count"], 1)
        for bundle in result["bundles"]:
            self.assertEqual(verify_bundle(bundle["files"]), [], bundle["finding_id"])

    def test_the_refuted_candidate_is_refused(self):
        result = export_bundles(REAL)
        statuses = {f["finding_id"]: f["status"] for f in REAL["findings"]}
        for refusal in result["refusals"]:
            self.assertNotEqual(statuses.get(refusal["finding_id"]), "VERIFIED")


if __name__ == "__main__":
    unittest.main()
