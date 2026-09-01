"""Attack chains must compose only verified findings, and never inflate severity."""

import unittest

from sechelix_core.attack_chains import CONFIRMED, POTENTIAL, correlate, correlate_report


def finding(fid, title, status="VERIFIED", surface=(), hypotheses=()):
    return {
        "finding_id": fid,
        "title": title,
        "status": status,
        "severity": "MEDIUM",
        "affected_surface": list(surface),
        "catalog_hypothesis_ids": list(hypotheses),
    }


ATO_PARTS = [
    finding("SHX-F-1", "Login response differs for known accounts, allowing user enumeration",
            hypotheses=["SHX-AUTH-L01"]),
    finding("SHX-F-2", "Password reset token is predictable and does not expire",
            hypotheses=["SHX-AUTH-L04"]),
    finding("SHX-F-3", "Recovery flow skips the second factor / MFA step-up",
            hypotheses=["SHX-AUTH-L09"]),
]

XTENANT_PARTS = [
    finding("SHX-F-10", "Report lookup omits the tenant ownership predicate (IDOR)",
            hypotheses=["SHX-AUTHZ-L02"]),
    finding("SHX-F-11", "Signed URL for object keys leaks in a client response",
            hypotheses=["SHX-PRIV-L20"]),
    finding("SHX-F-12", "Export endpoint returns many objects per request",
            hypotheses=["SHX-API-L07"]),
]


class ConfirmedChainTests(unittest.TestCase):
    def test_three_modest_findings_compose_into_account_takeover(self):
        chains = correlate(ATO_PARTS)
        ato = [c for c in chains if c["chain_id"] == "CHAIN-ATO-001"]
        self.assertTrue(ato, "the account takeover chain should be recognized")
        chain = ato[0]
        self.assertEqual(chain["status"], CONFIRMED)
        self.assertEqual(chain["severity"], "CRITICAL")
        self.assertEqual(chain["claim_status"], "VERIFIED_COMPOSITION")

    def test_a_confirmed_chain_cites_every_component(self):
        chain = [c for c in correlate(ATO_PARTS) if c["chain_id"] == "CHAIN-ATO-001"][0]
        cited = {c["finding_id"] for c in chain["component_findings"]}
        self.assertEqual(cited, {"SHX-F-1", "SHX-F-2", "SHX-F-3"})
        self.assertEqual(chain["missing_links"], [])

    def test_a_chain_states_its_prerequisites(self):
        chain = [c for c in correlate(ATO_PARTS) if c["chain_id"] == "CHAIN-ATO-001"][0]
        self.assertTrue(chain["prerequisites"])
        self.assertTrue(chain["rationale"])

    def test_cross_tenant_exfiltration_composes(self):
        chain = [c for c in correlate(XTENANT_PARTS) if c["chain_id"] == "CHAIN-XTENANT-001"][0]
        self.assertEqual(chain["status"], CONFIRMED)
        self.assertEqual(chain["severity"], "CRITICAL")


class HonestyTests(unittest.TestCase):
    def test_unverified_components_produce_a_potential_chain_with_no_severity(self):
        parts = [dict(f, status="HYPOTHESIS") for f in ATO_PARTS]
        chain = [c for c in correlate(parts) if c["chain_id"] == "CHAIN-ATO-001"][0]
        self.assertEqual(chain["status"], POTENTIAL)
        self.assertEqual(chain["severity"], "UNASSIGNED")
        self.assertEqual(chain["claim_status"], "HYPOTHESIS")
        self.assertEqual(len(chain["unverified_components"]), 3)

    def test_a_refuted_component_does_not_confirm_a_chain(self):
        parts = list(ATO_PARTS[:2]) + [dict(ATO_PARTS[2], status="FALSE_POSITIVE")]
        chain = [c for c in correlate(parts) if c["chain_id"] == "CHAIN-ATO-001"][0]
        self.assertEqual(chain["status"], POTENTIAL)
        self.assertEqual(chain["severity"], "UNASSIGNED")

    def test_a_partial_chain_names_what_is_missing(self):
        chain = [c for c in correlate(ATO_PARTS[:2]) if c["chain_id"] == "CHAIN-ATO-001"][0]
        self.assertEqual(chain["status"], POTENTIAL)
        self.assertEqual(len(chain["missing_links"]), 1)
        self.assertIn("step-up", chain["missing_links"][0].lower())

    def test_unrelated_findings_produce_no_chain(self):
        parts = [
            finding("SHX-F-90", "Verbose stack trace in an error page"),
            finding("SHX-F-91", "Missing cache-control header on a static asset"),
        ]
        self.assertEqual(correlate(parts), [])

    def test_a_signal_does_not_match_inside_a_longer_word(self):
        """Both ends matter. A leading boundary alone leaves the mirror-image bug."""
        from sechelix_core.attack_chains import _signal_pattern

        for signal, text in [
            ("race", "verbose stack trace"),      # the original bug
            ("list", "event listener"),           # only a trailing boundary catches this
            ("run", "runtime error"),
            ("send", "sender address"),
            ("tool", "a toolkit module"),
            ("mcp", "mcpx transport"),
        ]:
            with self.subTest(signal=signal, text=text):
                self.assertIsNone(_signal_pattern(signal).search(text))

    def test_plural_forms_that_reviewers_actually_write_still_match(self):
        """Boundaries must not make the signal list stop firing on real prose."""
        from sechelix_core.attack_chains import _signal_pattern

        for signal, text in [
            ("tools", "agent registers tools without an allowlist"),
            ("lists", "endpoint lists all invoices"),
            ("replays", "webhook replays are not rejected"),
            ("credits", "credits the ledger twice"),
            ("uploads", "uploads the archive to an external host"),
        ]:
            with self.subTest(signal=signal, text=text):
                self.assertIsNotNone(_signal_pattern(signal).search(text))

    def test_incidental_findings_compose_into_nothing(self):
        parts = [
            finding("SHX-F-80", "Verbose stack trace in an error page"),
            finding("SHX-F-81", "Event listener registered on every render"),
            finding("SHX-F-82", "Runtime error exposes a file path"),
        ]
        self.assertEqual(correlate(parts), [])

    def test_severity_is_never_taken_from_a_component(self):
        """A chain of MEDIUM findings is CRITICAL because of the outcome, not a bump."""
        for part in ATO_PARTS:
            self.assertEqual(part["severity"], "MEDIUM")
        chain = [c for c in correlate(ATO_PARTS) if c["chain_id"] == "CHAIN-ATO-001"][0]
        self.assertEqual(chain["severity"], "CRITICAL")

    def test_confirmed_chains_are_ordered_before_potential_ones(self):
        parts = ATO_PARTS + [dict(f, status="HYPOTHESIS") for f in XTENANT_PARTS]
        chains = correlate(parts)
        statuses = [c["status"] for c in chains]
        self.assertEqual(statuses, sorted(statuses, key=lambda s: s != CONFIRMED))


class ReportIntegrationTests(unittest.TestCase):
    def test_correlating_a_report_summarizes_counts(self):
        result = correlate_report({"report_id": "REPORT-X", "findings": ATO_PARTS})
        self.assertEqual(result["report_id"], "REPORT-X")
        self.assertEqual(result["confirmed_count"], 1)
        self.assertTrue(result["notes"])

    def test_a_report_without_findings_is_rejected(self):
        with self.assertRaises(ValueError):
            correlate_report({"report_id": "REPORT-X"})

    def test_the_real_case_study_report_produces_no_invented_chain(self):
        import json
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        report = json.loads((root / "examples/report.example.json").read_text(encoding="utf-8"))
        result = correlate_report(report)
        self.assertEqual(
            result["confirmed_count"], 0,
            "a two-finding report must not yield a confirmed multi-step chain",
        )


if __name__ == "__main__":
    unittest.main()
