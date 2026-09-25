from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sechelix_runner.pentest.gateway import (
    PolicyToolGateway,
    ToolOperation,
    ToolPolicyDenied,
)
from sechelix_runner.pentest.scope import ScopeEndpoint, TargetScope
from sechelix_runner.sandbox import ExecutionMode


class ToolGatewayTests(unittest.TestCase):
    def staging_scope(self) -> TargetScope:
        return TargetScope(
            primary_url="https://app.example.test",
            mode=ExecutionMode.STAGING,
            endpoints=(ScopeEndpoint("app.example.test"),),
            ownership_verified=True,
            verification_method="operator-fixture",
        )

    def test_network_target_must_be_inside_scope(self) -> None:
        gateway = PolicyToolGateway(scope=self.staging_scope(), repository_root=".")
        gateway.authorize(ToolOperation(
            tool="http-api",
            target="https://app.example.test/api/me",
            network=True,
            purpose="authorization fixture verification",
        ))
        with self.assertRaises(ToolPolicyDenied):
            gateway.authorize(ToolOperation(
                tool="http-api",
                target="https://example.org/",
                network=True,
                purpose="should never leave scope",
            ))

    def test_filesystem_target_cannot_escape_repository(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            gateway = PolicyToolGateway(repository_root=tmp)
            gateway.authorize(ToolOperation(
                tool="semgrep",
                target=".",
                purpose="static review",
            ))
            with self.assertRaises(ToolPolicyDenied):
                gateway.authorize(ToolOperation(
                    tool="gitleaks",
                    target="../outside",
                    purpose="secret scan",
                ))

    def test_high_risk_is_fail_closed(self) -> None:
        gateway = PolicyToolGateway(scope=self.staging_scope(), repository_root=".")
        with self.assertRaises(ToolPolicyDenied):
            gateway.authorize(ToolOperation(
                tool="browser",
                target="https://app.example.test/admin",
                network=True,
                risk="HIGH",
                purpose="requires separately reviewed policy",
            ))

    def test_destructive_declaration_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            ToolOperation(
                tool="http-api",
                target="https://app.example.test/delete",
                network=True,
                destructive=True,
                purpose="not permitted",
            )

    def test_decisions_are_auditable_without_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "evidence" / "tool-decisions.jsonl"
            gateway = PolicyToolGateway(
                scope=self.staging_scope(),
                repository_root=tmp,
                evidence_log=log,
            )
            gateway.authorize(ToolOperation(
                tool="browser",
                target="https://app.example.test/account",
                network=True,
                authentication_context="buyer-session-ref",
                evidence_output="network-events.jsonl",
                purpose="map authenticated account surface",
            ))
            row = json.loads(log.read_text(encoding="utf-8").splitlines()[0])
            self.assertTrue(row["allowed"])
            self.assertEqual(row["operation"]["authentication_context"], "buyer-session-ref")
            self.assertNotIn("cookie", log.read_text(encoding="utf-8").lower())


if __name__ == "__main__":
    unittest.main()
