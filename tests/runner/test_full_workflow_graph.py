from __future__ import annotations

import tempfile
import unittest
from types import SimpleNamespace

from sechelix_core.remediation import PASS, StageResult
from sechelix_runner.executor import MockExecutor, NodeOutcome
from sechelix_runner.graph import GraphNode, ReasonerGraph
from sechelix_runner.pentest import (
    CHAIN_LINKS,
    ChainEvidence,
    FindingPromotionSpec,
    FullWorkflowGraphExecutor,
    LiveContextBuilder,
    RemediationJobTemplate,
    parse_full_workflow_spec,
)
from sechelix_runner.providers.reasoning import verifier_view
from sechelix_runner.roles import NodeRole, NodeStatus
from sechelix_runner.runner import Runner


def candidate() -> dict[str, object]:
    return {
        "claim": "Buyer A can read Buyer B order through the object endpoint",
        "location": "GET /api/orders/{id}",
        "why": "Controlled staging evidence crossed the ownership boundary.",
        "hypothesis_ids": ["SHX-AUTHZ-L02"],
    }


def chain() -> dict[str, ChainEvidence]:
    return {
        name: ChainEvidence(
            statement=f"{name} established by controlled evidence",
            evidence_ids=(f"EV-LINK-{index:02d}",),
        )
        for index, name in enumerate(CHAIN_LINKS, start=1)
    }


def assessment(row: dict[str, object]) -> dict[str, object]:
    return {
        "candidate_ref": verifier_view(row)["candidate_ref"],
        "classification": "VERIFIED",
        "claim": row["claim"],
        "location": row["location"],
        "why": "Independent reconstruction could not refute the boundary failure.",
        "refutation_attempt": "Repeated with an isolated buyer identity.",
        "evidence_ids": ["EV-VERIFY"],
        "hypothesis_ids": ["SHX-AUTHZ-L02"],
    }


def workflow_graph() -> ReasonerGraph:
    return ReasonerGraph(
        [
            GraphNode(
                "independent-verifier",
                NodeRole.INDEPENDENT_VERIFIER,
                mandatory=True,
            ),
            GraphNode(
                "remediator",
                NodeRole.REMEDIATOR,
                depends_on=("independent-verifier",),
                mandatory=True,
            ),
            GraphNode(
                "patch-verifier",
                NodeRole.PATCH_VERIFIER,
                depends_on=("remediator",),
                mandatory=True,
            ),
            GraphNode(
                "release-gate",
                NodeRole.RELEASE_GATE,
                depends_on=("patch-verifier",),
                mandatory=True,
            ),
        ]
    )


class FakeCheckRunner:
    def __init__(self, workspace: str) -> None:
        self.workspace = workspace

    def run_test(self, stage_name, spec):
        return SimpleNamespace(
            stage=StageResult(
                stage_name,
                PASS,
                "bounded check passed",
                (f"EV-{stage_name.upper()}",),
            )
        )


class FullWorkflowGraphTests(unittest.TestCase):
    def test_verifier_materializes_findings_and_binds_remediation_without_preseed(self) -> None:
        row = candidate()
        candidate_ref = verifier_view(row)["candidate_ref"]
        verifier_output = assessment(row)

        with tempfile.TemporaryDirectory() as tmp:
            executor = FullWorkflowGraphExecutor(
                MockExecutor(
                    {
                        "independent-verifier": NodeOutcome(
                            status=NodeStatus.SUCCEEDED,
                            output={"assessments": [verifier_output]},
                        )
                    }
                ),
                (
                    FindingPromotionSpec(
                        candidate_ref=candidate_ref,
                        title="Cross-account order read bypasses ownership boundary",
                        severity="HIGH",
                        confidence="HIGH",
                        evidence_chain=chain(),
                        verifier="independent-verifier-live",
                    ),
                ),
                (
                    RemediationJobTemplate(
                        candidate_ref=candidate_ref,
                        patch_id="PATCH-AUTHZ-1",
                        workspace=tmp,
                        existing_test_targets=("tests.test_existing",),
                        regression_test_targets=("tests.test_security_regression",),
                        patch_diff_review={"deltas": []},
                        independent_test_targets=(
                            "tests.test_independent_security_verification",
                        ),
                    ),
                ),
                check_runner_factory=FakeCheckRunner,
            )
            result = Runner(
                executor=executor,
                context_builder_factory=LiveContextBuilder,
            ).run(
                workflow_graph(),
                {"candidates": [row]},
            )

        self.assertEqual(result.unsatisfied_mandatory, [])
        self.assertIs(
            result.records["independent-verifier"].status,
            NodeStatus.SUCCEEDED,
        )
        finding = result.outputs["independent-verifier"]["verified_findings"][0]
        self.assertEqual(finding["status"], "VERIFIED")
        self.assertTrue(finding["finding_id"].startswith("SHX-F-LIVE-"))
        self.assertEqual(
            result.outputs["independent-verifier"]["finding_bindings"],
            [{"candidate_ref": candidate_ref, "finding_id": finding["finding_id"]}],
        )
        self.assertIn(
            "verified_findings",
            result.context_views["remediator"]["source_ids"],
        )
        patch = result.outputs["remediator"]["patches"][0]
        self.assertEqual(patch["finding_id"], finding["finding_id"])
        self.assertFalse(patch["applied"])
        self.assertIn("findings", result.context_views["release-gate"]["source_ids"])
        self.assertIs(result.records["release-gate"].status, NodeStatus.SUCCEEDED)

    def test_missing_promotion_spec_fails_closed_before_remediation(self) -> None:
        row = candidate()
        verifier_output = assessment(row)
        executor = FullWorkflowGraphExecutor(
            MockExecutor(
                {
                    "independent-verifier": NodeOutcome(
                        status=NodeStatus.SUCCEEDED,
                        output={"assessments": [verifier_output]},
                    )
                }
            ),
            (),
            (),
            check_runner_factory=FakeCheckRunner,
        )
        result = Runner(
            executor=executor,
            context_builder_factory=LiveContextBuilder,
        ).run(workflow_graph(), {"candidates": [row]})

        self.assertIs(
            result.records["independent-verifier"].status,
            NodeStatus.FAILED,
        )
        self.assertIn(
            "promotion specs must match VERIFIED assessments exactly",
            result.records["independent-verifier"].error,
        )
        self.assertIs(result.records["remediator"].status, NodeStatus.BLOCKED)
        self.assertIs(result.records["release-gate"].status, NodeStatus.BLOCKED)

    def test_remediation_template_must_match_verified_candidate_exactly(self) -> None:
        row = candidate()
        candidate_ref = verifier_view(row)["candidate_ref"]
        verifier_output = assessment(row)
        executor = FullWorkflowGraphExecutor(
            MockExecutor(
                {
                    "independent-verifier": NodeOutcome(
                        status=NodeStatus.SUCCEEDED,
                        output={"assessments": [verifier_output]},
                    )
                }
            ),
            (
                FindingPromotionSpec(
                    candidate_ref=candidate_ref,
                    title="Cross-account order read",
                    severity="HIGH",
                    confidence="HIGH",
                    evidence_chain=chain(),
                    verifier="independent-verifier-live",
                ),
            ),
            (),
            check_runner_factory=FakeCheckRunner,
        )
        result = Runner(
            executor=executor,
            context_builder_factory=LiveContextBuilder,
        ).run(workflow_graph(), {"candidates": [row]})

        self.assertIs(
            result.records["independent-verifier"].status,
            NodeStatus.FAILED,
        )
        self.assertIn(
            "remediation templates must match canonical VERIFIED findings exactly",
            result.records["independent-verifier"].error,
        )

    def test_fixed_shape_spec_parser_builds_current_graph_inputs(self) -> None:
        row = candidate()
        candidate_ref = verifier_view(row)["candidate_ref"]
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "schema_version": "sechelix-full-workflow-spec/v1",
                "candidates": [
                    {
                        "candidate_ref": candidate_ref,
                        "title": "Cross-account order read",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "evidence_chain": {
                            name: {
                                "statement": evidence.statement,
                                "evidence_ids": list(evidence.evidence_ids),
                            }
                            for name, evidence in chain().items()
                        },
                        "verifier": "independent-verifier-live",
                        "remediation": {
                            "patch_id": "PATCH-AUTHZ-1",
                            "workspace": tmp,
                            "existing_test_targets": ["tests.test_existing"],
                            "regression_test_targets": ["tests.test_regression"],
                            "patch_diff_review": {"deltas": []},
                            "independent_test_targets": [
                                "tests.test_independent_verification"
                            ],
                        },
                    }
                ],
            }
            spec = parse_full_workflow_spec(payload)

        self.assertEqual(
            [item.candidate_ref for item in spec.promotion_specs],
            [candidate_ref],
        )
        self.assertEqual(
            [item.candidate_ref for item in spec.remediation_templates],
            [candidate_ref],
        )
        self.assertFalse(spec.audit_view()["generic_command_surface"])

    def test_spec_parser_rejects_generic_command_fields(self) -> None:
        row = candidate()
        candidate_ref = verifier_view(row)["candidate_ref"]
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "schema_version": "sechelix-full-workflow-spec/v1",
                "candidates": [
                    {
                        "candidate_ref": candidate_ref,
                        "title": "Cross-account order read",
                        "severity": "HIGH",
                        "confidence": "HIGH",
                        "evidence_chain": {
                            name: {
                                "statement": evidence.statement,
                                "evidence_ids": list(evidence.evidence_ids),
                            }
                            for name, evidence in chain().items()
                        },
                        "verifier": "independent-verifier-live",
                        "remediation": {
                            "patch_id": "PATCH-AUTHZ-1",
                            "workspace": tmp,
                            "existing_test_targets": ["tests.test_existing"],
                            "regression_test_targets": ["tests.test_regression"],
                            "patch_diff_review": {"deltas": []},
                            "independent_test_targets": [
                                "tests.test_independent_verification"
                            ],
                            "command": "arbitrary-command",
                        },
                    }
                ],
            }
            with self.assertRaisesRegex(
                Exception,
                "remediation fields mismatch",
            ):
                parse_full_workflow_spec(payload)

    def test_templates_expose_no_generic_command_surface(self) -> None:
        fields = set(RemediationJobTemplate.__dataclass_fields__)
        self.assertNotIn("command", fields)
        self.assertNotIn("argv", fields)
        self.assertNotIn("shell", fields)


if __name__ == "__main__":
    unittest.main()
