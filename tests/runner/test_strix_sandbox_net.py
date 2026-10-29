from __future__ import annotations

import subprocess
import unittest
from unittest.mock import patch

from sechelix_runner.pentest.strix_sandbox_net import (
    SandboxNetworkError,
    isolated_strix_network,
    isolation_requested,
    rewrite_target_in_command,
)


def _record_docker(
    calls: list[list[str]],
    *,
    fail_on: str | None = None,
    inspect_members: str = "",
):
    def fake_run(command, **kwargs):
        if kwargs.get("shell") is not False:
            raise AssertionError("docker must never run through a shell")
        calls.append(list(command))
        verb = command[1] if len(command) > 1 else ""
        if fail_on is not None and verb == fail_on:
            return subprocess.CompletedProcess(command, 1, "", "boom")
        # `network inspect` reports which containers remain on the network.
        if command[1:3] == ["network", "inspect"]:
            return subprocess.CompletedProcess(command, 0, inspect_members, "")
        return subprocess.CompletedProcess(command, 0, "ok", "")

    return fake_run


class SandboxNetHelpers(unittest.TestCase):
    def test_isolation_requested_truthy_values(self) -> None:
        for v in ("1", "true", "YES", "on"):
            self.assertTrue(isolation_requested({"SECHELIX_STRIX_ISOLATE_NETWORK": v}))
        for v in ("", "0", "off", "no", "maybe"):
            self.assertFalse(isolation_requested({"SECHELIX_STRIX_ISOLATE_NETWORK": v}))
        self.assertFalse(isolation_requested({}))

    def test_rewrite_target_in_command(self) -> None:
        cmd = ("strix", "-n", "--target", "http://host.docker.internal:8077", "--scan-mode", "quick")
        out = rewrite_target_in_command(cmd, "http://sechelix-target:8077")
        self.assertEqual(out[3], "http://sechelix-target:8077")
        self.assertEqual(out[:3], ("strix", "-n", "--target"))

    def test_rewrite_target_requires_a_target_flag(self) -> None:
        with self.assertRaises(SandboxNetworkError):
            rewrite_target_in_command(("strix", "-n"), "http://x:1")


class IsolatedNetworkLifecycle(unittest.TestCase):
    def test_target_and_gateway_are_proxied_and_torn_down(self) -> None:
        calls: list[list[str]] = []
        with patch(
            "sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
            side_effect=_record_docker(calls),
        ):
            with isolated_strix_network(
                target_url="http://host.docker.internal:8077",
                gateway_base_url="http://127.0.0.1:8082/v1",
            ) as sandbox:
                # URLs rewritten to the fixed aliases, ports preserved.
                self.assertEqual(sandbox.target_url, "http://sechelix-target:8077")
                self.assertEqual(sandbox.gateway_base_url, "http://sechelix-gateway:8082/v1")
                self.assertEqual(
                    sandbox.allowed_hosts,
                    frozenset({"sechelix-target", "sechelix-gateway"}),
                )
                self.assertTrue(sandbox.network.startswith("sechelix-strix-iso-"))

        verbs = [(c[1], c) for c in calls]
        # internal network created
        create = [c for v, c in verbs if v == "network" and c[2] == "create"]
        self.assertEqual(len(create), 1)
        self.assertIn("--internal", create[0])
        # two proxies forward to the host ports via host.docker.internal
        runs = [c for v, c in verbs if v == "run"]
        self.assertEqual(len(runs), 2)
        joined = " ".join(" ".join(c) for c in runs)
        self.assertIn("TCP-LISTEN:8077,fork,reuseaddr", joined)
        self.assertIn("TCP:host.docker.internal:8077", joined)
        self.assertIn("TCP-LISTEN:8082,fork,reuseaddr", joined)
        self.assertIn("TCP:host.docker.internal:8082", joined)
        for c in runs:
            self.assertIn("host.docker.internal:host-gateway", c)  # --add-host value
        # proxies joined the internal net under the fixed aliases
        connects = [c for v, c in verbs if v == "network" and c[2] == "connect"]
        self.assertEqual(len(connects), 2)
        aliases = {c[c.index("--alias") + 1] for c in connects}
        self.assertEqual(aliases, {"sechelix-target", "sechelix-gateway"})
        # teardown removed both proxies and the network
        removed = [c for v, c in verbs if v in ("rm",) or (v == "network" and c[2] == "rm")]
        self.assertEqual(len([c for c in removed if c[1] == "rm"]), 2)
        self.assertTrue(any(c[1] == "network" and c[2] == "rm" for v, c in verbs))

    def test_no_gateway_proxies_only_the_target(self) -> None:
        calls: list[list[str]] = []
        with patch(
            "sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
            side_effect=_record_docker(calls),
        ):
            with isolated_strix_network(
                target_url="http://host.docker.internal:8077",
                gateway_base_url=None,
            ) as sandbox:
                self.assertIsNone(sandbox.gateway_base_url)
                self.assertEqual(sandbox.allowed_hosts, frozenset({"sechelix-target"}))
        runs = [c for c in calls if len(c) > 1 and c[1] == "run"]
        self.assertEqual(len(runs), 1)

    def test_teardown_runs_even_when_the_body_raises(self) -> None:
        calls: list[list[str]] = []
        with patch(
            "sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
            side_effect=_record_docker(calls),
        ):
            with self.assertRaises(RuntimeError):
                with isolated_strix_network(
                    target_url="http://host.docker.internal:8077"
                ):
                    raise RuntimeError("Strix blew up")
        self.assertTrue(any(c[1] == "rm" for c in calls if len(c) > 1))
        self.assertTrue(
            any(c[1] == "network" and len(c) > 2 and c[2] == "rm" for c in calls)
        )

    def test_teardown_force_removes_leftover_sandbox_and_network(self) -> None:
        # A timed-out run can leave Strix's sandbox attached to the per-run
        # network; teardown must force it off before removing the network, or
        # the network leaks and the orphan can be reused uncontained.
        calls: list[list[str]] = []
        with patch(
            "sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
            side_effect=_record_docker(calls, inspect_members="inspiring_nobel"),
        ):
            with isolated_strix_network(
                target_url="http://host.docker.internal:8077"
            ):
                pass
        # The leftover sandbox was force-removed...
        self.assertTrue(
            any(c[:2] == ["docker", "rm"] and "inspiring_nobel" in c for c in calls),
            calls,
        )
        # ...before the network was removed.
        rm_member = next(
            i for i, c in enumerate(calls)
            if c[:2] == ["docker", "rm"] and "inspiring_nobel" in c
        )
        net_rm = next(
            i for i, c in enumerate(calls)
            if c[1:3] == ["network", "rm"]
        )
        self.assertLess(rm_member, net_rm)

    def test_network_create_failure_is_reported(self) -> None:
        calls: list[list[str]] = []
        with patch(
            "sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
            side_effect=_record_docker(calls, fail_on="network"),
        ):
            with self.assertRaises(SandboxNetworkError):
                with isolated_strix_network(
                    target_url="http://host.docker.internal:8077"
                ):
                    self.fail("should not enter the body when setup fails")


if __name__ == "__main__":
    unittest.main()
