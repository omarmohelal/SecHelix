import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sechelix_runner.proof import FORBIDDEN_ACTIONS, PlanState, ProofClass, build_plan
from sechelix_runner.sandbox import (
    FORBIDDEN_HOSTS,
    ExecutionMode,
    NetworkDenied,
    NetworkPolicy,
    SandboxSpec,
    confine_path,
    is_loopback,
)


class NetworkDefaultDenyTests(unittest.TestCase):
    def test_a_fresh_policy_reaches_nothing(self) -> None:
        self.assertFalse(NetworkPolicy(ExecutionMode.LOCAL).check("example.com", 443))

    def test_require_raises_when_ungranted(self) -> None:
        with self.assertRaises(NetworkDenied):
            NetworkPolicy(ExecutionMode.LOCAL).require("example.com", 443)

    def test_static_mode_grants_nothing_at_all(self) -> None:
        with self.assertRaises(NetworkDenied):
            NetworkPolicy(ExecutionMode.STATIC).grant(
                "127.0.0.1", 8080, purpose="callback", scope_id="S"
            )

    def test_a_grant_authorizes_exactly_one_host_and_port(self) -> None:
        policy = NetworkPolicy(ExecutionMode.LOCAL)
        policy.grant("127.0.0.1", 8080, protocol="http", purpose="ssrf callback", scope_id="S")
        self.assertTrue(policy.check("127.0.0.1", 8080, protocol="http"))
        self.assertFalse(policy.check("127.0.0.1", 8081, protocol="http"))
        self.assertFalse(policy.check("127.0.0.2", 8080, protocol="http"))

    def test_a_grant_without_a_purpose_is_refused(self) -> None:
        with self.assertRaises(NetworkDenied):
            NetworkPolicy(ExecutionMode.LOCAL).grant(
                "127.0.0.1", 8080, purpose="   ", scope_id="S"
            )

    def test_grants_expire(self) -> None:
        policy = NetworkPolicy(ExecutionMode.LOCAL)
        now = datetime.now(timezone.utc)
        policy.grant(
            "127.0.0.1", 8080, protocol="http", purpose="p", scope_id="S",
            ttl_seconds=60, now=now,
        )
        self.assertTrue(policy.check("127.0.0.1", 8080, protocol="http", now=now))
        self.assertFalse(
            policy.check("127.0.0.1", 8080, protocol="http", now=now + timedelta(seconds=61))
        )

    def test_public_oob_services_are_refused_by_construction(self) -> None:
        """Routing target traffic through a third party is not a proof method."""
        policy = NetworkPolicy(ExecutionMode.LOCAL)
        for host in FORBIDDEN_HOSTS:
            with self.subTest(host=host):
                with self.assertRaises(NetworkDenied):
                    policy.grant(host, 443, purpose="oob", scope_id="S")

    def test_subdomains_of_forbidden_hosts_are_refused(self) -> None:
        with self.assertRaises(NetworkDenied):
            NetworkPolicy(ExecutionMode.LOCAL).grant(
                "abc123.interact.sh", 443, purpose="oob", scope_id="S"
            )

    def test_every_decision_is_recorded(self) -> None:
        policy = NetworkPolicy(ExecutionMode.LOCAL)
        policy.check("example.com", 443)
        snapshot = policy.snapshot()
        self.assertEqual(snapshot["default"], "DENY")
        self.assertEqual(len(snapshot["decisions"]), 1)
        self.assertFalse(snapshot["decisions"][0]["allowed"])

    def test_loopback_detection_resolves_addresses(self) -> None:
        for host in ("127.0.0.1", "localhost", "::1"):
            self.assertTrue(is_loopback(host), host)
        for host in ("10.0.0.1", "evil-localhost.example.com"):
            self.assertFalse(is_loopback(host), host)


class SandboxSpecTests(unittest.TestCase):
    def test_defaults_are_restrictive(self) -> None:
        spec = SandboxSpec()
        self.assertEqual(spec.validate(), [])
        self.assertFalse(spec.privileged)
        self.assertFalse(spec.network_enabled)
        self.assertTrue(spec.read_only_root)

    def test_privileged_is_rejected(self) -> None:
        self.assertIn(
            "privileged containers are not permitted", SandboxSpec(privileged=True).validate()
        )

    def test_added_capabilities_require_review(self) -> None:
        problems = SandboxSpec(add_capabilities=("SYS_ADMIN",)).validate()
        self.assertTrue(any("SYS_ADMIN" in problem for problem in problems))

    def test_writable_mount_outside_workspace_is_rejected(self) -> None:
        problems = SandboxSpec(mounts=(("/etc", "/etc", False),)).validate()
        self.assertTrue(any("writable mount" in problem for problem in problems))

    def test_docker_args_deny_the_network_by_default(self) -> None:
        args = SandboxSpec().docker_args()
        for expected in (
            "--network=none", "--cap-drop=ALL", "--read-only",
            "--security-opt=no-new-privileges",
        ):
            self.assertIn(expected, args)


class PathConfinementTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workspace = tempfile.mkdtemp()

    def test_paths_inside_the_workspace_resolve(self) -> None:
        resolved = confine_path("a/b.txt", self.workspace)
        self.assertTrue(resolved.startswith(str(Path(self.workspace).resolve())))

    def test_dotdot_traversal_is_refused(self) -> None:
        with self.assertRaises(PermissionError):
            confine_path("../../etc/passwd", self.workspace)

    def test_nested_traversal_that_escapes_is_refused(self) -> None:
        with self.assertRaises(PermissionError):
            confine_path("a/../../../etc/passwd", self.workspace)

    def test_traversal_that_stays_inside_is_allowed(self) -> None:
        confine_path("a/../b.txt", self.workspace)

    def test_absolute_path_outside_is_refused(self) -> None:
        with self.assertRaises(PermissionError):
            confine_path("/etc/passwd", self.workspace)


class ProofPlanTests(unittest.TestCase):
    ALL_AUTHORITY = {
        "identity_a_credentials",
        "identity_b_credentials",
        "fixture_write_access",
        "fixture_endpoint_access",
        "local_browser_runtime",
        "local_callback_listener",
        "fixture_filesystem",
    }

    def test_every_class_produces_a_complete_plan(self) -> None:
        for proof_class in ProofClass:
            with self.subTest(proof_class=proof_class):
                plan = build_plan(proof_class, "F-1", available_authority=self.ALL_AUTHORITY)
                self.assertIs(plan.state, PlanState.READY)
                self.assertTrue(plan.actions)
                self.assertTrue(plan.expected_secure_behavior)
                self.assertTrue(plan.expected_vulnerable_behavior)
                self.assertTrue(plan.stop_conditions)

    def test_missing_authority_blocks_rather_than_weakens(self) -> None:
        """Observation without authority would not establish attacker control."""
        plan = build_plan(ProofClass.AUTHORIZATION_IDOR, "F-1", available_authority=set())
        self.assertIs(plan.state, PlanState.BLOCKED)
        self.assertIn("identity_a_credentials", plan.blocker)
        self.assertIn("attacker control", plan.blocker)

    def test_partial_authority_still_blocks(self) -> None:
        plan = build_plan(
            ProofClass.AUTHORIZATION_IDOR, "F-1",
            available_authority={"identity_a_credentials"},
        )
        self.assertIs(plan.state, PlanState.BLOCKED)

    def test_production_is_never_actively_proved(self) -> None:
        plan = build_plan(
            ProofClass.XSS_EXECUTION, "F-1",
            available_authority=self.ALL_AUTHORITY, environment="PRODUCTION",
        )
        self.assertIs(plan.state, PlanState.BLOCKED)
        self.assertIn("production", plan.blocker)

    def test_no_plan_contains_a_forbidden_action(self) -> None:
        for proof_class in ProofClass:
            plan = build_plan(proof_class, "F-1", available_authority=self.ALL_AUTHORITY)
            blob = " ".join(plan.actions).lower()
            for forbidden in FORBIDDEN_ACTIONS:
                with self.subTest(proof_class=proof_class, forbidden=forbidden):
                    self.assertNotIn(forbidden, blob)

    def test_ssrf_plan_uses_a_local_listener_not_a_public_service(self) -> None:
        plan = build_plan(ProofClass.SSRF_CALLBACK, "F-1", available_authority=self.ALL_AUTHORITY)
        blob = " ".join(plan.actions + plan.preconditions).lower()
        self.assertIn("127.0.0.1", blob)
        for host in FORBIDDEN_HOSTS:
            self.assertNotIn(host, blob)

    def test_every_plan_carries_stop_conditions_and_forbidden_actions(self) -> None:
        data = build_plan(
            ProofClass.RACE_IDEMPOTENCY, "F-1", available_authority=self.ALL_AUTHORITY
        ).to_dict()
        self.assertTrue(data["stop_conditions"])
        self.assertTrue(data["forbidden_actions"])


if __name__ == "__main__":
    unittest.main()
