from __future__ import annotations

import tempfile
import unittest

from sechelix_core.remediation import PASS, StageResult
from sechelix_runner.executor import MockExecutor, NodeOutcome
from sechelix_runner.graph import GraphNode, ReasonerGraph
from sechelix_runner.pentest import (
    CandidateSelector,
    ChainEvidence,
    FullWorkflowExecutor,
    FullWorkflowRule,
    FullWorkflowSpec,
    LiveContextBuilder,
    RemediationTemplate,
    parse_full_workflow_spec,
)
from sechelix_runner.providers.reasoning import verifier_view
from sechelix_runner.roles import NodeRole, NodeStatus
from sechelix_runner.runner import Runner


def candidate() -> dict[str, object]:
    return {
        "claim": "Buyer A can read Buyer B order through the object endpoint",
        "location": "GET /api/orders/{id}",
        "why": "Controlled staging reproduction crossed the owner boundary.",
        "hypothesis_ids": ["SHX-AUTHZ-L02"],
    }


def chain() -> dict[str, ChainEvidence]:
    names = (
        "attacker_control",
        "reachability",
        "boundary_failure",
        "safe_reproduction",
        "impact",
        "preconditions",
        "root_cause",
    )
    return {
        name: ChainEvidence(
            statement=f"{name} established by controlled fixture evidence",
            evidence_ids=(f"EV-LIVE-{index:02d}",),
        )
        for index, name in enumerate(names, start=1)
    }


def spec(workspace: str) -> FullWorkflowSpec:
    return FullWorkflowSpec(
        (
            FullWorkflowRule(
                selector=CandidateSelector(
                    claim=str(candidate()["claim"]),
                    location=str(candidate()["location"]),
                    hypothesis_ids=("SHX-AUTHZ-L02",),
                ),
                title="Cross-account order read bypasses ownership boundary",
                severity="HIGH",
                confidence="HIGH",
                evidence_chain=chain(),
                verifier="independent-verifier-live",
                remediation=RemediationTemplate(
                    patch_id="PATCH-AUTHZ-1",
                    workspace=workspace,
                    existing_test_targets=("tests.test_existing",),
                    regression_test_targets=("tests.test_security_regression",),
                    patch_diff_review={"deltas": []},
                    independent_verification=StageResult(
                        "independent_verification",
                        PASS,
                        "independent patch verification passed",
                        ("EV-PATCH-VERIFY",),
                    ),
                ),
            ),
        )
    )


def graph() -> ReasonerGraph:
    return ReasonerGraph(
        [
            GraphNode(
                "independent-verifier",
                NodeRole.INDEPENDENT_VERIFIER,
                mandatory=True,
            ),
            GraphNode(
                "finding-materializer",
                NodeRole.FINDING_MATERIALIZER,
                depends_on=("independent-verifier",),
                mandatory=True,
            ),
            GraphNode(
                "remediator",
                NodeRole.REMEDIATOR,
                depends_on=("finding-materializer",),
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
        return type(
            "Check",
            (),
            {
                "stage": StageResult(
                    stage_name,
                    PASS,
                    "bounded fake check passed",
                    (f"EV-{stage_name.upper()}",),
                )
            },
        )()


class FullWorkflowTests(unittest.TestCase):
    def test_same_run_materializes_finding_then_remediates_without_preseed(self) -> None:
        item = candidate()
        ref = verifier_view(dict(item))["candidate_ref"]
        assessment = {
            "candidate_ref": ref,
            "classification": "VERIFIED",
            "claim": item["claim"],
            "location": item["location"],
            "why": "Independent reconstruction could not refute the boundary failure.",
            "refutation_attempt": "Repeated with an isolated buyer session.",
            "evidence_ids": ["EV-VERIFY"],
            "hypothesis_ids": ["SHX-AUTHZ-L02"],
        }
        delegate = MockExecutor(
            {
                "independent-verifier": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    output={"assessments": [assessment]},
                )
            }
        )
        world = {
            "candidates": [item],
            "evidence": [
                {"evidence_id": "EV-VERIFY"},
                *[
                    {"evidence_id": f"EV-LIVE-{index:02d}"}
                    for index in range(1, 8)
                ],
            ],
        }
        self.assertNotIn("verified_findings", world)

        with tempfile.TemporaryDirectory() as tmp:
            executor = FullWorkflowExecutor(
                delegate,
                spec(tmp),
                check_runner_factory=FakeCheckRunner,
            )
            result = Runner(
                executor=executor,
                context_builder_factory=LiveContextBuilder,
            ).run(graph(), world)

        self.assertEqual(result.unsatisfied_mandatory, [])
        materialized = result.outputs["finding-materializer"]
        self.assertEqual(len(materialized["verified_findings"]), 1)
        finding = materialized["verified_findings"][0]
        self.assertEqual(finding["status"], "VERIFIED")
        self.assertTrue(finding["finding_id"].startswith("SHX-F-LIVE-"))
        self.assertFalse(
            materialized["materialization"]["preseeded_intermediate_state"]
        )
        self.assertEqual(
            result.outputs["remediator"]["remediation_results"][0]["outcome"],
            "READY_FOR_REVIEW",
        )
        self.assertEqual(
            result.outputs["patch-verifier"]["patch_verification"]["status"],
            "READY_FOR_REVIEW",
        )

    def test_verified_assessment_without_exact_rule_blocks_materialization(self) -> None:
        item = candidate()
        ref = verifier_view(dict(item))["candidate_ref"]
        assessment = {
            "candidate_ref": ref,
            "classification": "VERIFIED",
            "claim": item["claim"],
            "location": item["location"],
            "why": "Could not refute.",
            "refutation_attempt": "Independent replay.",
            "evidence_ids": ["EV-VERIFY"],
        }
        delegate = MockExecutor(
            {
                "independent-verifier": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    output={"assessments": [assessment]},
                )
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            wrong = spec(tmp)
            wrong_rule = FullWorkflowRule(
                selector=CandidateSelector(
                    claim="Different exact claim",
                    location="GET /api/orders/{id}",
                    hypothesis_ids=("SHX-AUTHZ-L02",),
                ),
                title=wrong.rules[0].title,
                severity=wrong.rules[0].severity,
                confidence=wrong.rules[0].confidence,
                evidence_chain=wrong.rules[0].evidence_chain,
                verifier=wrong.rules[0].verifier,
                remediation=wrong.rules[0].remediation,
            )
            result = Runner(
                executor=FullWorkflowExecutor(
                    delegate,
                    FullWorkflowSpec((wrong_rule,)),
                    check_runner_factory=FakeCheckRunner,
                ),
                context_builder_factory=LiveContextBuilder,
            ).run(
                graph(),
                {
                    "candidates": [item],
                    "evidence": [
                        {"evidence_id": "EV-VERIFY"},
                        *[
                            {"evidence_id": f"EV-{index:02d}"}
                            for index in range(1, 8)
                        ],
                    ],
                },
            )

        self.assertIs(
            result.records["finding-materializer"].status,
            NodeStatus.BLOCKED,
        )
        self.assertIn(
            "no exact full-workflow rule",
            result.records["finding-materializer"].blocker,
        )
        self.assertIs(result.records["remediator"].status, NodeStatus.BLOCKED)

    def test_non_verified_assessment_needs_no_remediation_job(self) -> None:
        item = candidate()
        ref = verifier_view(dict(item))["candidate_ref"]
        delegate = MockExecutor(
            {
                "independent-verifier": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    output={
                        "assessments": [
                            {
                                "candidate_ref": ref,
                                "classification": "FALSE_POSITIVE",
                                "claim": item["claim"],
                                "location": item["location"],
                                "why": "Clean control disproved the claim.",
                                "refutation_attempt": "Replayed against clean control.",
                                "evidence_ids": [],
                            }
                        ]
                    },
                )
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = Runner(
                executor=FullWorkflowExecutor(
                    delegate,
                    spec(tmp),
                    check_runner_factory=FakeCheckRunner,
                ),
                context_builder_factory=LiveContextBuilder,
            ).run(
                graph(),
                {"candidates": [item], "evidence": []},
            )

        self.assertEqual(result.unsatisfied_mandatory, [])
        self.assertEqual(
            result.outputs["finding-materializer"]["verified_findings"],
            [],
        )
        self.assertTrue(result.outputs["remediator"]["no_verified_findings"])
        self.assertEqual(
            result.outputs["patch-verifier"]["patch_verification"]["status"],
            "NOT_REQUIRED",
        )

    def test_promotion_chain_cannot_cite_absent_same_run_evidence(self) -> None:
        item = candidate()
        ref = verifier_view(dict(item))["candidate_ref"]
        delegate = MockExecutor(
            {
                "independent-verifier": NodeOutcome(
                    status=NodeStatus.SUCCEEDED,
                    output={
                        "assessments": [
                            {
                                "candidate_ref": ref,
                                "classification": "VERIFIED",
                                "claim": item["claim"],
                                "location": item["location"],
                                "why": "Could not refute.",
                                "refutation_attempt": "Independent replay.",
                                "evidence_ids": ["EV-VERIFY"],
                                "hypothesis_ids": ["SHX-AUTHZ-L02"],
                            }
                        ]
                    },
                )
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = Runner(
                executor=FullWorkflowExecutor(
                    delegate,
                    spec(tmp),
                    check_runner_factory=FakeCheckRunner,
                ),
                context_builder_factory=LiveContextBuilder,
            ).run(
                graph(),
                {
                    "candidates": [item],
                    "evidence": [{"evidence_id": "EV-VERIFY"}],
                },
            )

        self.assertIs(
            result.records["finding-materializer"].status,
            NodeStatus.BLOCKED,
        )
        self.assertIn(
            "absent from the same-run least-context view",
            result.records["finding-materializer"].blocker,
        )

    def test_parser_refuses_extra_fields_and_generic_command_surface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            payload = {
                "schema_version": "1.0",
                "rules": [
                    {
                        "candidate": {
                            "claim": candidate()["claim"],
                            "location": candidate()["location"],
                            "hypothesis_ids": ["SHX-AUTHZ-L02"],
                        },
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
                            "patch_id": "PATCH-1",
                            "workspace": tmp,
                            "existing_test_targets": ["tests.test_existing"],
                            "regression_test_targets": ["tests.test_regression"],
                            "patch_diff_review": {"deltas": []},
                            "independent_verification": {
                                "status": "PASS",
                                "detail": "passed",
                                "evidence_ids": ["EV-PATCH-VERIFY"],
                            },
                            "command": "rm -rf /",
                        },
                    }
                ],
            }
            with self.assertRaises(Exception):
                parse_full_workflow_spec(payload)


if __name__ == "__main__":
    unittest.main()
