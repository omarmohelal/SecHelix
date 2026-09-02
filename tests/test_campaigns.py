"""Campaigns must count root causes, not findings, and never call unproven work done."""

import json
import unittest
from pathlib import Path

from sechelix_core.campaigns import (
    BLOCKED,
    COMPLETE,
    IN_PROGRESS,
    NOT_STARTED,
    PATCHED_UNPROVEN,
    build_campaigns,
    render_markdown,
)

ROOT = Path(__file__).resolve().parents[1]

CAUSE_A = "Scope every object read by the session tenant."
CAUSE_B = "Verify the webhook signature before acting on the payload."


def finding(fid, cause=CAUSE_A, status="VERIFIED", resolution="OPEN",
            regression="NOT_RUN", severity="HIGH", repository="app"):
    payload = {
        "finding_id": fid,
        "status": status,
        "severity": severity,
        "resolution": resolution,
        "repository": repository,
        "regression": {"status": regression, "command": "x",
                       "assertion": "x", "evidence_ids": []},
    }
    if cause is not None:
        payload["remediation"] = {"root_cause_fix": cause, "evidence_ids": []}
    return payload


class GroupingTests(unittest.TestCase):
    def test_many_findings_collapse_into_few_root_causes(self):
        findings = [finding(f"SHX-F-{i}", CAUSE_A) for i in range(8)]
        findings += [finding(f"SHX-F-B{i}", CAUSE_B) for i in range(5)]
        result = build_campaigns(findings)
        self.assertEqual(result["summary"]["verified_findings"], 13)
        self.assertEqual(result["summary"]["root_causes"], 2)

    def test_the_headline_counts_observations_and_causes(self):
        findings = [finding("SHX-F-1"), finding("SHX-F-2", status="HYPOTHESIS")]
        summary = build_campaigns(findings)["summary"]
        self.assertEqual(summary["observations"], 2)
        self.assertEqual(summary["verified_findings"], 1)
        self.assertEqual(summary["root_causes"], 1)

    def test_unverified_findings_never_join_a_campaign(self):
        """Grouping hypotheses by root cause invents a cause for a maybe."""
        findings = [finding("SHX-F-1", status="HYPOTHESIS"),
                    finding("SHX-F-2", status="LIKELY_BUT_UNPROVEN"),
                    finding("SHX-F-3", status="FALSE_POSITIVE")]
        result = build_campaigns(findings)
        self.assertEqual(result["campaigns"], [])
        self.assertEqual(result["summary"]["root_causes"], 0)

    def test_a_verified_finding_without_a_root_cause_is_unattributed_not_hidden(self):
        result = build_campaigns([finding("SHX-F-1", cause=None)])
        self.assertEqual(result["campaigns"], [])
        self.assertEqual(result["unattributed_findings"], ["SHX-F-1"])
        self.assertEqual(result["summary"]["unattributed_verified_findings"], 1)

    def test_a_campaign_lists_every_affected_repository(self):
        findings = [finding("SHX-F-1", repository="api"),
                    finding("SHX-F-2", repository="web"),
                    finding("SHX-F-3", repository="api")]
        campaign = build_campaigns(findings)["campaigns"][0]
        self.assertEqual(campaign["affected_repositories"], ["api", "web"])

    def test_root_causes_are_never_inferred(self):
        """Two different recorded causes stay two campaigns even if they look similar."""
        findings = [finding("SHX-F-1", "Scope reads by tenant."),
                    finding("SHX-F-2", "Scope reads by the tenant.")]
        self.assertEqual(build_campaigns(findings)["summary"]["root_causes"], 2)


class CompletionTests(unittest.TestCase):
    def test_a_campaign_with_open_findings_is_not_complete(self):
        campaign = build_campaigns([finding("SHX-F-1", resolution="OPEN")])["campaigns"][0]
        self.assertNotEqual(campaign["status"], COMPLETE)
        self.assertEqual(campaign["remaining_findings"], ["SHX-F-1"])

    def test_patched_without_regression_proof_is_not_complete(self):
        """'We changed the code' and 'we proved it works' are different claims."""
        campaign = build_campaigns([
            finding("SHX-F-1", resolution="FIXED", regression="NOT_RUN")
        ])["campaigns"][0]
        self.assertEqual(campaign["status"], PATCHED_UNPROVEN)
        self.assertIn("unverified", campaign["remaining_risk"])

    def test_patched_with_passing_regression_is_complete(self):
        campaign = build_campaigns([
            finding("SHX-F-1", resolution="FIXED", regression="PASS")
        ])["campaigns"][0]
        self.assertEqual(campaign["status"], COMPLETE)

    def test_a_failing_regression_is_not_complete(self):
        campaign = build_campaigns([
            finding("SHX-F-1", resolution="FIXED", regression="FAIL")
        ])["campaigns"][0]
        self.assertNotEqual(campaign["status"], COMPLETE)
        self.assertEqual(campaign["regression_status"], "FAIL")

    def test_one_unpatched_finding_holds_the_whole_campaign_open(self):
        campaign = build_campaigns([
            finding("SHX-F-1", resolution="FIXED", regression="PASS"),
            finding("SHX-F-2", resolution="OPEN"),
        ])["campaigns"][0]
        self.assertEqual(campaign["status"], IN_PROGRESS)
        self.assertEqual(campaign["remaining_findings"], ["SHX-F-2"])

    def test_remaining_risk_names_the_findings_rather_than_a_percentage(self):
        """'90% complete' hides which one is open."""
        findings = [finding(f"SHX-F-{i}", resolution="FIXED", regression="PASS")
                    for i in range(9)]
        findings.append(finding("SHX-F-OPEN", resolution="OPEN"))
        campaign = build_campaigns(findings)["campaigns"][0]
        self.assertIn("SHX-F-OPEN", campaign["remaining_risk"])
        self.assertNotIn("%", campaign["remaining_risk"])


class OwnershipTests(unittest.TestCase):
    def test_an_unowned_campaign_says_so(self):
        campaign = build_campaigns([finding("SHX-F-1")])["campaigns"][0]
        self.assertIsNone(campaign["owner"])
        self.assertTrue(any("nobody owns" in n for n in campaign["notes"]))

    def test_an_owner_can_be_assigned_by_root_cause(self):
        result = build_campaigns([finding("SHX-F-1")], owners={CAUSE_A: "omar"})
        self.assertEqual(result["campaigns"][0]["owner"], "omar")
        self.assertEqual(result["campaigns"][0]["notes"], [])

    def test_a_deadline_can_be_assigned(self):
        result = build_campaigns([finding("SHX-F-1")], deadlines={CAUSE_A: "2026-10-01"})
        self.assertEqual(result["campaigns"][0]["deadline"], "2026-10-01")


class PriorityTests(unittest.TestCase):
    def test_priority_comes_from_the_worst_member_and_raises_nothing(self):
        findings = [finding("SHX-F-1", severity="LOW"),
                    finding("SHX-F-2", severity="CRITICAL")]
        self.assertEqual(build_campaigns(findings)["campaigns"][0]["priority"], "CRITICAL")

    def test_an_all_low_campaign_stays_low(self):
        findings = [finding("SHX-F-1", severity="LOW"), finding("SHX-F-2", severity="LOW")]
        self.assertEqual(build_campaigns(findings)["campaigns"][0]["priority"], "LOW")


class RenderTests(unittest.TestCase):
    def test_the_headline_reads_as_a_funnel(self):
        findings = [finding(f"SHX-F-{i}") for i in range(5)]
        findings += [finding(f"SHX-F-B{i}", CAUSE_B) for i in range(3)]
        findings += [finding("SHX-F-H", status="HYPOTHESIS")]
        text = render_markdown(build_campaigns(findings))
        self.assertIn("9 observations", text)
        self.assertIn("8 verified findings", text)
        self.assertIn("2 root causes", text)

    def test_an_unassigned_campaign_is_visibly_unassigned(self):
        text = render_markdown(build_campaigns([finding("SHX-F-1")]))
        self.assertIn("**unassigned**", text)

    def test_an_empty_result_says_so_plainly(self):
        text = render_markdown(build_campaigns([]))
        self.assertIn("No verified finding", text)


class RealReportTests(unittest.TestCase):
    def test_the_published_case_study_produces_a_coherent_campaign_view(self):
        report = json.loads((ROOT / "examples/report.example.json").read_text(encoding="utf-8"))
        result = build_campaigns(report["findings"])
        self.assertEqual(result["summary"]["observations"], len(report["findings"]))
        verified = sum(1 for f in report["findings"]
                       if str(f.get("status", "")).upper() == "VERIFIED")
        self.assertEqual(result["summary"]["verified_findings"], verified)
        self.assertLessEqual(result["summary"]["root_causes"], verified)


if __name__ == "__main__":
    unittest.main()
