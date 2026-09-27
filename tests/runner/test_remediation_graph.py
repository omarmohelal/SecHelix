from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sechelix_core.remediation import FAIL, PASS, READY, StageResult
from sechelix_runner.executor import MockExecutor
from sechelix_runner.graph import GraphNode, ReasonerGraph
from sechelix_runner.pentest import (
    LiveContextBuilder,
    RemediationGraphError,
    RemediationGraphExecutor,
    RemediationJob,
)
from sechelix_runner.roles import NodeRole, NodeStatus
from sechelix_runner.runner import Runner


def verified_finding(finding_id: str = "SHX-F-1") -> dict[str, object]:
    return {
        "finding_id": finding_id,
        "status": "VERIFIED",
    }


def graph() -> ReasonerGraph:
    return ReasonerGraph(
        [
            GraphNode("remediator", NodeRole.REMEDIATOR, mandatory=True),
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


def job(workspace: str, finding_id: str = "SHX-F-1") -> RemediationJob:
    return RemediationJob(
        finding_id=finding_id,
        patch_id=f"PATCH-{finding_id}",
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
    )


class FakeCheckRunner:
    def __init__(self, workspace: str, *, regression_status: str = PASS) -> None:
        self.workspace = workspace
        self.regression_status = regression_status
        self.calls: list[str] = []

    def run_test(self, stage_name, spec):
        self.calls.append(stage_name)
        status = (
            self.regression_status
            if stage_name == "vulnerability_regression"
            else PASS
        )
        return SimpleNamespace(
            stage=StageResult(
                stage_name,
                status,
                "fake bounded check result",
                (f"EV-{stage_name.upper()}",),
            )
        )


def world() -> dict[str, object]:
    finding = verified_finding()
    return {
        "verified_findings": [finding],
        "findings": [finding],
        "node_records": [],
    }


class RemediationGraphExecutorTests(unittest.TestCase):
    def test_ready_remediation_products_flow_through_patch_verifier_to_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            checks: list[FakeCheckRunner] = []

            def factory(workspace: str) -> FakeCheckRunner:
                runner = FakeCheckRunner(workspace)
                checks.append(runner)
                return runner

            executor = RemediationGraphExecutor(
                MockExecutor(),
                (job(tmp),),
                check_runner_factory=factory,
            )
            result = Runner(
                executor=executor,
                context_builder_factory=LiveContextBuilder,
            ).run(graph(), world())

        self.assertEqual(result.unsatisfied_mandatory, [])
        self.assertIs(result.records["remediator"].status, NodeStatus.SUCCEEDED)
        self.assertIs(result.records["patch-verifier"].status, NodeStatus.SUCCEEDED)
        self.assertIs(result.records["release-gate"].status, NodeStatus.SUCCEEDED)
        self.assertEqual(checks[0].calls, ["existing_tests", "vulnerability_regression"])

        remediation = result.outputs["remediator"]["remediation_results"][0]
        self.assertEqual(remediation["outcome"], READY)
        self.assertFalse(remediation["applied"])
        patch = result.outputs["remediator"]["patches"][0]
        self.assertFalse(patch["applied"])

        verification = result.outputs["patch-verifier"]["patch_verification"]
        self.assertEqual(verification["status"], READY)
        self.assertFalse(verification["applied"])
        self.assertTrue(verification["human_review_required"])
        self.assertIn(
            "remediation_results",
            result.context_views["patch-verifier"]["source_ids"],
        )
        self.assertIn(
            "patch_verification",
            result.context_views["release-gate"]["source_ids"],
        )

    def test_failed_regression_blocks_patch_verifier_and_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executor = RemediationGraphExecutor(
                MockExecutor(),
                (job(tmp),),
                check_runner_factory=lambda workspace: FakeCheckRunner(
                    workspace,
                    regression_status=FAIL,
                ),
            )
            result = Runner(
                executor=executor,
                context_builder_factory=LiveContextBuilder,
            ).run(graph(), world())

        self.assertIs(result.records["remediator"].status, NodeStatus.SUCCEEDED)
        self.assertIs(result.records["patch-verifier"].status, NodeStatus.BLOCKED)
        self.assertIn(
            "not READY_FOR_REVIEW",
            result.records["patch-verifier"].blocker,
        )
        self.assertIs(result.records["release-gate"].status, NodeStatus.BLOCKED)
        self.assertIn("patch-verifier", result.unsatisfied_mandatory)
        self.assertIn("release-gate", result.unsatisfied_mandatory)

    def test_job_set_must_match_verified_findings_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            executor = RemediationGraphExecutor(
                MockExecutor(),
                (job(first), job(second, "SHX-F-EXTRA")),
                check_runner_factory=FakeCheckRunner,
            )
            result = Runner(
                executor=executor,
                context_builder_factory=LiveContextBuilder,
            ).run(graph(), world())

        self.assertIs(result.records["remediator"].status, NodeStatus.BLOCKED)
        self.assertIn("extra=['SHX-F-EXTRA']", result.records["remediator"].blocker)
        self.assertIs(result.records["patch-verifier"].status, NodeStatus.BLOCKED)

    def test_unverified_finding_is_refused_before_any_check_executes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executor = RemediationGraphExecutor(
                MockExecutor(),
                (job(tmp),),
                check_runner_factory=FakeCheckRunner,
            )
            bad_world = world()
            bad_world["verified_findings"] = [
                {"finding_id": "SHX-F-1", "status": "CANDIDATE"}
            ]
            result = Runner(
                executor=executor,
                context_builder_factory=LiveContextBuilder,
            ).run(graph(), bad_world)

        self.assertIs(result.records["remediator"].status, NodeStatus.FAILED)
        self.assertIn("not canonical VERIFIED", result.records["remediator"].error)

    def test_job_has_no_generic_command_surface(self) -> None:
        fields = set(RemediationJob.__dataclass_fields__)
        self.assertNotIn("command", fields)
        self.assertNotIn("argv", fields)
        self.assertNotIn("shell", fields)

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(Exception):
                RemediationJob(
                    finding_id="SHX-F-1",
                    patch_id="PATCH-1",
                    workspace=str(Path(tmp).resolve()),
                    existing_test_targets=("--help",),
                    regression_test_targets=("tests.test_regression",),
                    patch_diff_review={"deltas": []},
                    independent_verification=StageResult(
                        "independent_verification",
                        PASS,
                        "ok",
                    ),
                )

    def test_independent_verification_pass_requires_evidence_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(RemediationGraphError):
                RemediationJob(
                    finding_id="SHX-F-1",
                    patch_id="PATCH-1",
                    workspace=tmp,
                    existing_test_targets=("tests.test_existing",),
                    regression_test_targets=("tests.test_regression",),
                    patch_diff_review={"deltas": []},
                    independent_verification=StageResult(
                        "independent_verification",
                        PASS,
                        "claimed pass without evidence",
                    ),
                )

    def test_duplicate_patch_ids_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_job = job(first, "SHX-F-1")
            second_job = RemediationJob(
                finding_id="SHX-F-2",
                patch_id=first_job.patch_id,
                workspace=second,
                existing_test_targets=("tests.test_existing",),
                regression_test_targets=("tests.test_regression",),
                patch_diff_review={"deltas": []},
                independent_verification=StageResult(
                    "independent_verification",
                    PASS,
                    "ok",
                    ("EV-PATCH-VERIFY-2",),
                ),
            )
            with self.assertRaises(RemediationGraphError):
                RemediationGraphExecutor(MockExecutor(), (first_job, second_job))


if __name__ == "__main__":
    unittest.main()
