import json
import unittest
from pathlib import Path

from sechelix_runner.compliance import (
    FORBIDDEN_TERMS,
    ControlState,
    assess,
    framework_of,
    load_family_mappings,
    summarise,
)
from sechelix_runner.roles import NodeRole, NodeStatus
from sechelix_runner.telemetry import NodeRecord

ROOT = Path(__file__).resolve().parents[2]


def record(role: NodeRole, status: NodeStatus) -> NodeRecord:
    return NodeRecord(
        run_id="R",
        node_id=role.value.lower(),
        role=role,
        node_version="1",
        target_commit="c",
        scope_id="s",
        status=status,
    )


def all_roles(status: NodeStatus) -> dict[str, NodeRecord]:
    return {r.value.lower(): record(r, status) for r in NodeRole}


class MappingSourceTests(unittest.TestCase):
    def test_mappings_come_from_the_catalog_not_a_parallel_table(self) -> None:
        mappings = load_family_mappings(ROOT / "catalog" / "checks.json")
        catalog = json.loads((ROOT / "catalog" / "checks.json").read_text(encoding="utf-8"))
        self.assertEqual(set(mappings), {f["id"] for f in catalog["families"]})

    def test_every_family_is_covered_by_the_role_map(self) -> None:
        """A family with no lane would silently vanish from every report."""
        from sechelix_runner.compliance import FAMILY_TO_ROLE

        mappings = load_family_mappings(ROOT / "catalog" / "checks.json")
        self.assertEqual(set(mappings) - set(FAMILY_TO_ROLE), set())

    def test_framework_is_derived_from_the_control_id(self) -> None:
        self.assertEqual(framework_of("OWASP-ASVS:V2"), "OWASP-ASVS")
        self.assertEqual(framework_of("NIST-SSDF:PS.3"), "NIST-SSDF")

    def test_unrecognised_prefix_is_grouped_not_dropped(self) -> None:
        self.assertEqual(framework_of("SOMETHING-NEW:1"), "SOMETHING-NEW")


class StateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mappings = load_family_mappings(ROOT / "catalog" / "checks.json")

    def test_blocked_lanes_make_controls_unknown_not_evidenced(self) -> None:
        """Running out of budget must not read as "we checked and it was fine"."""
        assessments = assess(self.mappings, all_roles(NodeStatus.BLOCKED))
        self.assertTrue(assessments)
        for assessment in assessments:
            self.assertIs(assessment.state, ControlState.UNKNOWN)

    def test_examined_with_no_evidence_is_not_evidenced(self) -> None:
        assessments = assess(self.mappings, all_roles(NodeStatus.SUCCEEDED))
        states = {a.state for a in assessments}
        self.assertIn(ControlState.NOT_EVIDENCED, states)
        self.assertNotIn(ControlState.UNKNOWN, states)

    def test_verified_evidence_produces_evidenced(self) -> None:
        assessments = assess(
            self.mappings,
            all_roles(NodeStatus.SUCCEEDED),
            verified_evidence_by_family={"AUTHZ": ["EV-1", "EV-2"]},
        )
        evidenced = [a for a in assessments if a.state is ControlState.EVIDENCED]
        self.assertTrue(evidenced)
        self.assertEqual(evidenced[0].evidence_ids, ["EV-1", "EV-2"])

    def test_evidence_plus_an_unexamined_family_is_partial(self) -> None:
        records = all_roles(NodeStatus.SUCCEEDED)
        # Blind one lane that shares a control with an evidenced family.
        records[NodeRole.AUTHENTICATION.value.lower()] = record(
            NodeRole.AUTHENTICATION, NodeStatus.BLOCKED
        )
        assessments = assess(
            self.mappings,
            records,
            verified_evidence_by_family={"SESS": ["EV-9"]},
        )
        partial = [a for a in assessments if a.state is ControlState.PARTIAL]
        self.assertTrue(partial)
        self.assertIn("not examined", partial[0].rationale)

    def test_not_applicable_families_yield_not_applicable_controls(self) -> None:
        assessments = assess(
            self.mappings,
            all_roles(NodeStatus.SUCCEEDED),
            not_applicable_families={"AI", "CLOUD", "SUPPLY"},
        )
        self.assertTrue(
            any(a.state is ControlState.NOT_APPLICABLE for a in assessments)
        )

    def test_skipped_counts_as_examined(self) -> None:
        """An inapplicable lane answered the question; it owes no evidence."""
        assessments = assess(self.mappings, all_roles(NodeStatus.SKIPPED))
        self.assertNotIn(ControlState.UNKNOWN, {a.state for a in assessments})

    def test_every_assessment_carries_a_rationale(self) -> None:
        for assessment in assess(self.mappings, all_roles(NodeStatus.BLOCKED)):
            self.assertTrue(assessment.rationale)


class VocabularyTests(unittest.TestCase):
    def test_no_forbidden_term_appears_in_any_state(self) -> None:
        self.assertNotIn("COMPLIANT", [s.value for s in ControlState])
        self.assertNotIn("CERTIFIED", [s.value for s in ControlState])

    def test_report_never_claims_compliance(self) -> None:
        mappings = load_family_mappings(ROOT / "catalog" / "checks.json")
        report = summarise(
            assess(
                mappings,
                all_roles(NodeStatus.SUCCEEDED),
                verified_evidence_by_family={"AUTHZ": ["EV-1"]},
            )
        )
        # The disclaimer necessarily contains the word; exclude only that phrase.
        blob = json.dumps(report).lower().replace("does not determine compliance", "")
        for term in FORBIDDEN_TERMS:
            self.assertNotIn(term, blob)

    def test_report_states_that_unknown_means_nobody_looked(self) -> None:
        mappings = load_family_mappings(ROOT / "catalog" / "checks.json")
        report = summarise(assess(mappings, all_roles(NodeStatus.BLOCKED)))
        self.assertIn("nobody looked", report["disclaimer"].lower())

    def test_no_ai_fallback_exists_for_unmapped_controls(self) -> None:
        """An unmapped control stays UNKNOWN; nothing invents a mapping."""
        assessments = assess({"GHOST": ["OWASP-ASVS:V99"]}, all_roles(NodeStatus.SUCCEEDED))
        self.assertEqual(len(assessments), 1)
        self.assertIs(assessments[0].state, ControlState.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
