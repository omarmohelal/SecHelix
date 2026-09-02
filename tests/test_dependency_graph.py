"""A dependency verdict must never let 'we could not tell' read as 'we are fine'.

The rule under test everywhere in this file is that ``UNKNOWN`` is not
``NOT_EXPLOITABLE``. The rest — evidence on every claim, severity carried rather
than computed, the deciding link named — exists to keep that rule from being
worked around one field at a time.
"""

import itertools
import types
import unittest

from sechelix_core import dependency_graph
from sechelix_core.contracts import ContractValidationError, validate_contract
from sechelix_core.dependency_graph import (
    ADVISORY,
    CHAIN,
    CONFIRMED,
    EXPLOITABLE,
    EXTERNALLY_EXPOSED,
    IMPORTED,
    INSTALLED,
    NOT_EXPLOITABLE,
    NOT_STATED,
    REFUTED,
    UNASSIGNED,
    UNKNOWN,
    VULNERABLE_SYMBOL_USED,
    Advisory,
    DependencyGraphError,
    assess,
    build_report,
    link,
    network_capabilities,
    normalize_advisory,
    render_markdown,
)

OSV = {
    "id": "GHSA-abcd-efgh-ijkl",
    "aliases": ["CVE-2024-00001"],
    "summary": "unsafe deserialization in load()",
    "database_specific": {"severity": "HIGH"},
    "affected": [
        {
            "package": {"name": "pyyaml", "ecosystem": "PyPI"},
            "ranges": [{"type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "5.4"}]}],
        }
    ],
}

TRIVY = {
    "VulnerabilityID": "CVE-2024-00002",
    "PkgName": "lodash",
    "InstalledVersion": "4.17.20",
    "FixedVersion": "4.17.21",
    "Severity": "CRITICAL",
    "Title": "prototype pollution",
    "PrimaryURL": "https://example.invalid/advisory",
}


def chain(**states):
    """Build links for the named chain positions; anything omitted is not recorded."""
    links = []
    for index, name in enumerate(CHAIN):
        if name not in states:
            continue
        state = states[name]
        evidence = () if state == UNKNOWN else (f"EV-{index + 1:03d}",)
        links.append(link(name, state, statement=f"{name} was assessed", evidence_ids=evidence))
    return links


def whole_chain(state=CONFIRMED):
    return chain(**{name: state for name in CHAIN})


class AdvisoryNormalizationTests(unittest.TestCase):
    def test_an_osv_advisory_normalizes(self):
        advisory = normalize_advisory(OSV)
        self.assertEqual(advisory.advisory_id, "GHSA-abcd-efgh-ijkl")
        self.assertEqual(advisory.package, "pyyaml")
        self.assertEqual(advisory.ecosystem, "PyPI")
        self.assertEqual(advisory.fixed_version, "5.4")
        self.assertEqual(advisory.aliases, ("CVE-2024-00001",))

    def test_a_trivy_advisory_normalizes(self):
        advisory = normalize_advisory(TRIVY)
        self.assertEqual(advisory.advisory_id, "CVE-2024-00002")
        self.assertEqual(advisory.package, "lodash")
        self.assertEqual(advisory.installed_version, "4.17.20")
        self.assertEqual(advisory.fixed_version, "4.17.21")

    def test_a_stated_severity_is_carried_verbatim(self):
        for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            with self.subTest(label=label):
                advisory = normalize_advisory({**TRIVY, "Severity": label})
                self.assertEqual(advisory.severity, label)
                self.assertEqual(advisory.severity_source, ADVISORY)

    def test_an_advisory_with_no_severity_gets_none_invented(self):
        advisory = normalize_advisory({k: v for k, v in TRIVY.items() if k != "Severity"})
        self.assertEqual(advisory.severity, UNASSIGNED)
        self.assertEqual(advisory.severity_source, NOT_STATED)

    def test_a_scoring_vector_does_not_become_a_label(self):
        """Deriving HIGH from a vector would make this the source of the number."""
        raw = {k: v for k, v in OSV.items() if k != "database_specific"}
        raw["severity"] = [{"type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
        advisory = normalize_advisory(raw)
        self.assertEqual(advisory.severity, UNASSIGNED)
        self.assertEqual(advisory.severity_source, NOT_STATED)
        self.assertTrue(advisory.severity_vector.startswith("CVSS:3.1/"))

    def test_a_severity_word_outside_the_vocabulary_is_not_mapped(self):
        advisory = normalize_advisory({**TRIVY, "Severity": "MODERATE"})
        self.assertEqual(advisory.severity, UNASSIGNED)
        self.assertEqual(advisory.severity_source, NOT_STATED)

    def test_an_advisory_with_no_identifier_is_refused(self):
        with self.assertRaises(DependencyGraphError):
            normalize_advisory({"VulnerabilityID": "", "PkgName": "lodash"})

    def test_an_unrecognized_shape_is_refused(self):
        for raw in ({"name": "lodash"}, "CVE-2024-00002", None, []):
            with self.subTest(raw=raw), self.assertRaises(DependencyGraphError):
                normalize_advisory(raw)


class ChainTests(unittest.TestCase):
    def test_an_unknown_link_is_refused(self):
        with self.assertRaises(DependencyGraphError):
            link("REACHABLE", CONFIRMED, evidence_ids=["EV-001"])

    def test_an_unknown_state_is_refused(self):
        with self.assertRaises(DependencyGraphError):
            link(INSTALLED, "PROBABLY", evidence_ids=["EV-001"])

    def test_the_same_link_twice_is_refused(self):
        links = [link(INSTALLED, CONFIRMED, evidence_ids=["EV-001"]),
                 link(INSTALLED, REFUTED, evidence_ids=["EV-002"])]
        with self.assertRaises(DependencyGraphError):
            assess(OSV, links)

    def test_every_link_is_always_reported_even_when_nobody_assessed_it(self):
        """A chain that omits unassessed links reads as a shorter chain that passed."""
        verdict = assess(OSV, chain(INSTALLED=CONFIRMED))
        self.assertEqual([item.name for item in verdict.links], list(CHAIN))
        unassessed = [item for item in verdict.links if item.name != INSTALLED]
        self.assertTrue(all(item.state == UNKNOWN for item in unassessed))
        self.assertTrue(all(item.statement for item in unassessed))

    def test_a_link_with_no_statement_states_the_question_it_answers(self):
        item = link(IMPORTED, CONFIRMED, evidence_ids=["EV-001"])
        self.assertIn("does this codebase import the package", item.statement)


class VerdictTests(unittest.TestCase):
    def test_a_complete_confirmed_chain_is_exploitable(self):
        verdict = assess(OSV, whole_chain(CONFIRMED))
        self.assertEqual(verdict.verdict, EXPLOITABLE)
        self.assertEqual(verdict.deciding_link, EXTERNALLY_EXPOSED)
        self.assertEqual(verdict.decided_by_state, CONFIRMED)
        self.assertTrue(verdict.actionable)
        self.assertTrue(verdict.deciding_evidence_ids)

    def test_an_evidenced_refutation_rules_it_out_and_names_the_link(self):
        verdict = assess(OSV, chain(INSTALLED=CONFIRMED, IMPORTED=REFUTED))
        self.assertEqual(verdict.verdict, NOT_EXPLOITABLE)
        self.assertEqual(verdict.deciding_link, IMPORTED)
        self.assertEqual(verdict.decided_by_state, REFUTED)
        self.assertTrue(verdict.ruled_out)
        self.assertIn("EV-002", verdict.reason)

    def test_the_earliest_break_is_the_one_reported(self):
        verdict = assess(OSV, chain(IMPORTED=REFUTED, EXTERNALLY_EXPOSED=REFUTED))
        self.assertEqual(verdict.deciding_link, IMPORTED)

    def test_a_refutation_outranks_an_unknown(self):
        verdict = assess(
            OSV,
            chain(INSTALLED=UNKNOWN, VULNERABLE_SYMBOL_USED=REFUTED),
        )
        self.assertEqual(verdict.verdict, NOT_EXPLOITABLE)
        self.assertEqual(verdict.deciding_link, VULNERABLE_SYMBOL_USED)

    def test_an_unassessed_link_leaves_the_verdict_unknown_and_names_it(self):
        verdict = assess(OSV, chain(INSTALLED=CONFIRMED, IMPORTED=CONFIRMED))
        self.assertEqual(verdict.verdict, UNKNOWN)
        self.assertEqual(verdict.deciding_link, VULNERABLE_SYMBOL_USED)
        self.assertIn("not proof of unreachability", verdict.reason)

    def test_every_verdict_cites_the_evidence_of_the_link_that_decided_it(self):
        for links in (whole_chain(CONFIRMED), chain(IMPORTED=REFUTED)):
            with self.subTest(links=len(links)):
                verdict = assess(OSV, links)
                self.assertTrue(verdict.deciding_evidence_ids)
                self.assertLessEqual(set(verdict.deciding_evidence_ids), set(verdict.evidence_ids))


class UnknownIsNotACleanResultTests(unittest.TestCase):
    """The single most important rule in the module, attacked from every side."""

    def test_no_chain_without_a_refutation_can_ever_be_ruled_out(self):
        for states in itertools.product((CONFIRMED, UNKNOWN), repeat=len(CHAIN)):
            links = chain(**dict(zip(CHAIN, states)))
            with self.subTest(states=states):
                verdict = assess(OSV, links)
                self.assertNotEqual(verdict.verdict, NOT_EXPLOITABLE)
                self.assertFalse(verdict.ruled_out)
                expected = EXPLOITABLE if UNKNOWN not in states else UNKNOWN
                self.assertEqual(verdict.verdict, expected)

    def test_an_unevidenced_refutation_cannot_clear_a_dependency(self):
        """A refutation without evidence is a claim, not a proof."""
        links = [link(INSTALLED, CONFIRMED, evidence_ids=["EV-001"]),
                 link(IMPORTED, REFUTED, statement="I looked and it is not imported")]
        verdict = assess(OSV, links)
        self.assertEqual(verdict.verdict, UNKNOWN)
        self.assertEqual(verdict.deciding_link, IMPORTED)
        self.assertEqual(verdict.downgraded[0][0], IMPORTED)
        self.assertEqual(verdict.downgraded[0][1], REFUTED)

    def test_an_unevidenced_confirmation_cannot_condemn_one_either(self):
        links = [link(name, CONFIRMED, statement="asserted") for name in CHAIN]
        verdict = assess(OSV, links)
        self.assertEqual(verdict.verdict, UNKNOWN)
        self.assertEqual(len(verdict.downgraded), len(CHAIN))

    def test_the_contract_refuses_a_clean_verdict_decided_by_an_unknown_link(self):
        artifact = build_report([assess(OSV, chain(INSTALLED=CONFIRMED))])
        assessment = artifact["assessments"][0]
        self.assertEqual(assessment["verdict"], UNKNOWN)
        assessment["verdict"] = NOT_EXPLOITABLE
        with self.assertRaises(ContractValidationError):
            validate_contract("dependency-exploitability", artifact)

    def test_the_contract_refuses_a_clean_verdict_with_no_evidence(self):
        artifact = build_report([assess(OSV, chain(IMPORTED=REFUTED))])
        artifact["assessments"][0]["deciding_evidence_ids"] = []
        with self.assertRaises(ContractValidationError):
            validate_contract("dependency-exploitability", artifact)

    def test_the_contract_refuses_an_unknown_verdict_dressed_with_evidence(self):
        artifact = build_report([assess(OSV, chain(INSTALLED=CONFIRMED))])
        artifact["assessments"][0]["deciding_evidence_ids"] = ["EV-001"]
        with self.assertRaises(ContractValidationError):
            validate_contract("dependency-exploitability", artifact)

    def test_the_rendered_table_says_undetermined_is_not_ruled_out(self):
        artifact = build_report([assess(OSV, chain(INSTALLED=CONFIRMED))])
        rendered = render_markdown(artifact)
        self.assertIn("Undetermined is not ruled out", rendered)
        self.assertIn("UNKNOWN", rendered)

    def test_the_counts_never_hide_the_undetermined(self):
        artifact = build_report([
            assess(OSV, chain(INSTALLED=CONFIRMED)),
            assess(TRIVY, whole_chain(CONFIRMED)),
        ])
        self.assertEqual(artifact["counts"], {EXPLOITABLE: 1, NOT_EXPLOITABLE: 0, UNKNOWN: 1})


class SeverityTests(unittest.TestCase):
    def test_severity_does_not_move_a_verdict(self):
        links = chain(INSTALLED=CONFIRMED, IMPORTED=CONFIRMED)
        verdicts = {
            label: assess(normalize_advisory({**TRIVY, "Severity": label}), links).verdict
            for label in ("CRITICAL", "LOW")
        }
        self.assertEqual(verdicts["CRITICAL"], verdicts["LOW"])
        self.assertEqual(verdicts["CRITICAL"], UNKNOWN)

    def test_a_critical_advisory_with_an_unproven_chain_is_still_unknown(self):
        """Severity is not a substitute for reachability, however loud it is."""
        verdict = assess(TRIVY, chain(INSTALLED=CONFIRMED))
        self.assertEqual(verdict.advisory.severity, "CRITICAL")
        self.assertEqual(verdict.verdict, UNKNOWN)

    def test_the_chain_is_identical_whatever_the_severity_says(self):
        links = chain(INSTALLED=CONFIRMED, ATTACKER_CONTROLLED_INPUT=REFUTED)
        loud = assess(normalize_advisory({**TRIVY, "Severity": "CRITICAL"}), links).as_dict()
        quiet = assess(normalize_advisory({**TRIVY, "Severity": "LOW"}), links).as_dict()
        for key in ("verdict", "deciding_link", "decided_by_state", "links", "reason"):
            with self.subTest(key=key):
                self.assertEqual(loud[key], quiet[key])
        self.assertNotEqual(loud["severity"], quiet["severity"])

    def test_a_severity_the_advisory_never_stated_is_labelled_as_such(self):
        advisory = Advisory(advisory_id="CVE-2024-00003", package="left-pad")
        record = assess(advisory, chain(INSTALLED=CONFIRMED)).as_dict()
        self.assertEqual(record["severity"], UNASSIGNED)
        self.assertEqual(record["severity_source"], NOT_STATED)


class NoNetworkTests(unittest.TestCase):
    def test_the_module_holds_nothing_that_could_reach_the_network(self):
        self.assertEqual(network_capabilities(), ())

    def test_a_leaked_network_import_fails_the_module(self):
        dependency_graph.__dict__["urllib"] = types.ModuleType("urllib")
        try:
            self.assertTrue(network_capabilities())
            with self.assertRaises(DependencyGraphError):
                dependency_graph._refuse_network_capability()
        finally:
            del dependency_graph.__dict__["urllib"]
        self.assertEqual(network_capabilities(), ())

    def test_no_public_callable_offers_to_go_and_get_an_advisory(self):
        forbidden = ("fetch", "download", "request", "http", "curl", "pull", "refresh")
        for name, value in vars(dependency_graph).items():
            if name.startswith("_") or not callable(value):
                continue
            with self.subTest(name=name):
                self.assertFalse(any(word in name.lower() for word in forbidden))


class ContractTests(unittest.TestCase):
    def artifact(self):
        return build_report(
            [
                assess(OSV, whole_chain(CONFIRMED)),
                assess(TRIVY, chain(INSTALLED=CONFIRMED, IMPORTED=REFUTED)),
                assess({**TRIVY, "VulnerabilityID": "CVE-2024-00009"},
                       chain(INSTALLED=CONFIRMED)),
            ],
            repository="owner/app",
            commit="06ab8ca680d477b8005805d67ab44d11507e3321",
        )

    def test_a_built_report_satisfies_its_contract(self):
        validate_contract("dependency-exploitability", self.artifact())

    def test_every_assessment_carries_the_whole_chain(self):
        for assessment in self.artifact()["assessments"]:
            self.assertEqual([item["name"] for item in assessment["links"]], list(CHAIN))

    def test_two_assessments_for_one_advisory_are_refused(self):
        verdict = assess(OSV, whole_chain(CONFIRMED))
        with self.assertRaises(DependencyGraphError):
            build_report([verdict, verdict])

    def test_a_downgraded_link_reaches_the_artifact(self):
        artifact = build_report([assess(OSV, [link(IMPORTED, REFUTED, statement="asserted")])])
        validate_contract("dependency-exploitability", artifact)
        self.assertEqual(artifact["assessments"][0]["downgraded_links"][0]["name"], IMPORTED)

    def test_the_notes_state_the_rule_the_module_exists_for(self):
        notes = " ".join(self.artifact()["notes"])
        self.assertIn("UNKNOWN is not NOT_EXPLOITABLE", notes)
        self.assertIn("CVE presence is not exploitability", notes)
        self.assertIn("never recomputed", notes)

    def test_the_report_is_deterministic(self):
        self.assertEqual(self.artifact(), self.artifact())


if __name__ == "__main__":
    unittest.main()
