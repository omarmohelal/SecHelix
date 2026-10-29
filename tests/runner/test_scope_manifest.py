from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from sechelix_runner.pentest.gateway import (
    PolicyToolGateway,
    ToolOperation,
    ToolPolicyDenied,
)
from sechelix_runner.pentest.scope_manifest import (
    ScopeManifestError,
    load_operational_scope,
)
from sechelix_runner.sandbox import ExecutionMode


NOW = datetime(2026, 10, 1, 8, 0, tzinfo=timezone.utc)


def manifest() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "scope_id": "SCOPE-TEST-001",
        "project": "fixture",
        "authorization": {
            "confirmed": True,
            "basis": "OWNER",
            "statement": "Owner-authorized staging security assessment.",
            "authorized_by": "fixture-owner",
            "confirmed_at": "2026-10-01T07:00:00Z",
            "expires_at": "2026-10-02T07:00:00Z",
            "evidence_reference": "AUTH-001",
        },
        "mode": "STAGING",
        "in_scope": [
            {
                "id": "TGT-APP",
                "type": "SERVICE",
                "name": "staging app",
                "locator": "https://staging.example.test",
                "environment": "STAGING",
                "authorized": True,
                "allowed_actions": ["READ", "BOUNDED_TEST"],
                "restrictions": ["no real purchases"],
            }
        ],
        "out_of_scope": [
            "third-party.example.test",
            "/admin/billing",
        ],
        "allowed_tools": ["browser", "http-api", "strix"],
        "side_effects": [
            {
                "category": "MONEY",
                "allowed": False,
                "restriction": "Use fixtures only.",
            },
            {
                "category": "OTHER",
                "allowed": True,
                "restriction": "Only seeded staging state may be changed.",
            },
        ],
        "stop_conditions": [
            "stop on scope uncertainty",
            "stop before real customer or provider side effects",
        ],
    }


def write_manifest(root: Path, data: dict[str, object]) -> Path:
    path = root / "scope.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


class OperationalScopeManifestTests(unittest.TestCase):
    def test_valid_manifest_becomes_enforceable_target_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(Path(tmp), manifest())
            scope = load_operational_scope(path, now=NOW)

        self.assertEqual(scope.mode, ExecutionMode.STAGING)
        self.assertEqual(scope.authorization.scope_id, "SCOPE-TEST-001")
        self.assertEqual(scope.authorization.basis, "OWNER")
        self.assertTrue(scope.manifest_sha256.startswith("sha256:"))
        self.assertTrue(scope.tool_allowed("browser"))
        self.assertFalse(scope.tool_allowed("semgrep"))
        self.assertFalse(scope.side_effect_allowed("MONEY"))
        self.assertTrue(scope.side_effect_allowed("OTHER"))
        self.assertTrue(scope.allows_url("https://staging.example.test/api/me"))
        self.assertFalse(scope.allows_url("https://staging.example.test/admin/billing"))
        self.assertFalse(scope.allows_url("https://third-party.example.test/"))
        self.assertFalse(scope.allows_url("https://sub.staging.example.test/"))

    def test_expired_authorization_is_refused(self) -> None:
        data = manifest()
        data["authorization"]["expires_at"] = "2026-10-01T07:59:59Z"
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(Path(tmp), data)
            with self.assertRaisesRegex(ScopeManifestError, "expired"):
                load_operational_scope(path, now=NOW)

    def test_future_confirmation_is_refused(self) -> None:
        data = manifest()
        data["authorization"]["confirmed_at"] = "2026-10-01T09:00:00Z"
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(Path(tmp), data)
            with self.assertRaisesRegex(ScopeManifestError, "future"):
                load_operational_scope(path, now=NOW)

    def test_unconfirmed_or_unauthorized_target_is_refused_by_contract(self) -> None:
        data = manifest()
        data["in_scope"][0]["authorized"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(Path(tmp), data)
            with self.assertRaisesRegex(ScopeManifestError, "not authorized"):
                load_operational_scope(path, now=NOW)

    def test_ambiguous_out_of_scope_prose_never_becomes_policy(self) -> None:
        data = manifest()
        data["out_of_scope"] = ["anything owned by vendors"]
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(Path(tmp), data)
            with self.assertRaisesRegex(ScopeManifestError, "hostname"):
                load_operational_scope(path, now=NOW)

    def test_multiple_network_targets_require_explicit_primary(self) -> None:
        data = manifest()
        second = deepcopy(data["in_scope"][0])
        second["id"] = "TGT-API"
        second["name"] = "staging api"
        second["locator"] = "https://api.example.test"
        data["in_scope"].append(second)
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(Path(tmp), data)
            with self.assertRaisesRegex(ScopeManifestError, "primary_url"):
                load_operational_scope(path, now=NOW)
            scope = load_operational_scope(
                path,
                primary_url="https://api.example.test",
                now=NOW,
            )
        self.assertEqual(scope.primary_url, "https://api.example.test")
        self.assertTrue(scope.allows_url("https://staging.example.test/"))

    def test_primary_url_cannot_escape_manifest_targets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(Path(tmp), manifest())
            with self.assertRaisesRegex(ScopeManifestError, "allowed endpoints"):
                load_operational_scope(
                    path,
                    primary_url="https://outside.example.test",
                    now=NOW,
                )

    def test_production_safe_manifest_does_not_enable_active_testing(self) -> None:
        data = manifest()
        data["mode"] = "PRODUCTION_SAFE"
        data["production_restrictions"] = ["read-only smoke checks only"]
        with tempfile.TemporaryDirectory() as tmp:
            path = write_manifest(Path(tmp), data)
            with self.assertRaisesRegex(ScopeManifestError, "accepts only LOCAL or STAGING"):
                load_operational_scope(path, now=NOW)

    def test_gateway_enforces_manifest_tools_and_side_effects_and_logs_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write_manifest(root, manifest())
            scope = load_operational_scope(path, now=NOW)
            log = root / "tool-decisions.jsonl"
            gateway = PolicyToolGateway(
                scope=scope,
                repository_root=root,
                evidence_log=log,
            )

            gateway.authorize(
                ToolOperation(
                    tool="http-api",
                    target="https://staging.example.test/api/fixture",
                    network=True,
                    purpose="bounded staging fixture update",
                    actor="authz-specialist",
                    side_effect_category="OTHER",
                    evidence_output="http-evidence.jsonl",
                )
            )
            with self.assertRaisesRegex(ToolPolicyDenied, "not allowed"):
                gateway.authorize(
                    ToolOperation(
                        tool="semgrep",
                        target=".",
                        purpose="not in manifest allowlist",
                        actor="code-specialist",
                    )
                )
            with self.assertRaisesRegex(ToolPolicyDenied, "side-effect category"):
                gateway.authorize(
                    ToolOperation(
                        tool="http-api",
                        target="https://staging.example.test/api/checkout",
                        network=True,
                        purpose="real payment must stay denied",
                        actor="business-logic-specialist",
                        side_effect_category="MONEY",
                    )
                )

            rows = [
                json.loads(line)
                for line in log.read_text(encoding="utf-8").splitlines()
            ]

        allowed = rows[0]
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["scope_id"], "SCOPE-TEST-001")
        self.assertEqual(allowed["authorization"]["authorized_by"], "fixture-owner")
        self.assertEqual(allowed["operation"]["actor"], "authz-specialist")
        self.assertEqual(allowed["operation"]["evidence_output"], "http-evidence.jsonl")
        self.assertTrue(allowed["scope_manifest_sha256"].startswith("sha256:"))
        self.assertFalse(rows[1]["allowed"])
        self.assertFalse(rows[2]["allowed"])


if __name__ == "__main__":
    unittest.main()
