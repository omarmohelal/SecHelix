from __future__ import annotations

import subprocess
import time
import unittest
from unittest.mock import patch

from sechelix_runner.pentest.strix_sandbox_net import (
    SandboxNetworkError,
    _apply_egress_firewall,
    _firewall_script,
    _running_sandbox_ids,
    _sandbox_host_gateways,
    _valid_ip,
    firewalled_strix_sandbox,
    isolation_requested,
)


def _fake_docker(
    calls: list[list[str]],
    *,
    sandbox_id: str | None = "sbx123",
    gw4: str = "192.168.65.254",
    gw6: str = "",
):
    """A ``subprocess.run`` stand-in that models the docker calls we make."""

    def fake_run(command, **kwargs):
        if kwargs.get("shell") is not False:
            raise AssertionError("docker must never run through a shell")
        calls.append(list(command))
        verb = command[1] if len(command) > 1 else ""
        out = "ok"
        if verb == "ps":
            # Mirrors `docker ps --format '{{.ID}} {{.Image}}'`: one sandbox row
            # plus an unrelated container that must be ignored.
            rows = ["deadbeef alpine:3.20"]
            if sandbox_id:
                rows.insert(0, f"{sandbox_id} ghcr.io/usestrix/strix-sandbox:1.3.0")
            out = "\n".join(rows)
        elif verb == "exec" and "getent" in command:
            out = (f"{gw4} host.docker.internal" if "ahostsv4" in command
                   else (f"{gw6} host.docker.internal" if gw6 else ""))
        return subprocess.CompletedProcess(command, 0, out, "")

    return fake_run


class SandboxHelpers(unittest.TestCase):
    def test_isolation_requested_truthy_values(self) -> None:
        for v in ("1", "true", "YES", "on"):
            self.assertTrue(isolation_requested({"SECHELIX_STRIX_ISOLATE_NETWORK": v}))
        for v in ("", "0", "off", "no", "maybe"):
            self.assertFalse(isolation_requested({"SECHELIX_STRIX_ISOLATE_NETWORK": v}))
        self.assertFalse(isolation_requested({}))

    def test_valid_ip(self) -> None:
        self.assertEqual(_valid_ip("192.168.65.254"), "192.168.65.254")
        self.assertEqual(_valid_ip("fd00::1"), "fd00::1")
        for bad in ("", "host.docker.internal", "1.2.3.4; rm -rf /", "999.1.1.1"):
            self.assertIsNone(_valid_ip(bad))

    def test_firewall_script_accepts_target_then_drops_gateway(self) -> None:
        script = _firewall_script(ipv4_gw="192.168.65.254", ipv6_gw=None, target_port=8077)
        # established accept precedes the target accept, which precedes the drop.
        est = script.index("ESTABLISHED,RELATED -j ACCEPT")
        accept = script.index("--dport 8077 -j ACCEPT")
        drop = script.index("-d 192.168.65.254 -j DROP")
        self.assertLess(est, accept)
        self.assertLess(accept, drop)
        self.assertIn("iptables", script)
        self.assertNotIn("ip6tables", script)  # no v6 gateway given

    def test_firewall_script_covers_ipv6_when_present(self) -> None:
        script = _firewall_script(ipv4_gw="192.168.65.254", ipv6_gw="fd00::254", target_port=443)
        self.assertIn("ip6tables -A OUTPUT -d fd00::254 -j DROP", script)
        self.assertIn("iptables -A OUTPUT -d 192.168.65.254 -j DROP", script)

    def test_firewall_script_rejects_bad_port(self) -> None:
        with self.assertRaises(SandboxNetworkError):
            _firewall_script(ipv4_gw="192.168.65.254", ipv6_gw=None, target_port=0)

    def test_running_sandbox_ids_matches_image_name_not_tagless_ancestor(self) -> None:
        # A tagless `--filter ancestor=` resolves to :latest and matches nothing;
        # detection must match the sandbox image name and ignore other images.
        calls: list[list[str]] = []
        with patch("sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
                   side_effect=_fake_docker(calls, sandbox_id="sbx123")):
            ids = _running_sandbox_ids(docker="docker")
        self.assertEqual(ids, ["sbx123"])  # the alpine row is ignored
        self.assertNotIn("ancestor=ghcr.io/usestrix/strix-sandbox", calls[0])
        self.assertIn("{{.ID}} {{.Image}}", calls[0])

    def test_sandbox_host_gateways_parses_getent(self) -> None:
        calls: list[list[str]] = []
        with patch("sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
                   side_effect=_fake_docker(calls, gw4="192.168.65.254", gw6="fd00::254")):
            v4, v6 = _sandbox_host_gateways("sbx123", docker="docker")
        self.assertEqual(v4, "192.168.65.254")
        self.assertEqual(v6, "fd00::254")

    def test_apply_egress_firewall_runs_a_netns_sidecar(self) -> None:
        calls: list[list[str]] = []
        with patch("sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
                   side_effect=_fake_docker(calls)):
            _apply_egress_firewall(
                "sbx123", ipv4_gw="192.168.65.254", ipv6_gw=None,
                target_port=8077, docker="docker",
            )
        run = next(c for c in calls if c[1] == "run")
        self.assertIn("--net=container:sbx123", run)
        self.assertIn("NET_ADMIN", run)
        self.assertEqual(run[-2], "-c")
        self.assertIn("--dport 8077 -j ACCEPT", run[-1])


class FirewalledSandboxLifecycle(unittest.TestCase):
    def test_watcher_firewalls_the_sandbox_then_teardown_removes_it(self) -> None:
        calls: list[list[str]] = []
        with patch("sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
                   side_effect=_fake_docker(calls, sandbox_id="sbx123")):
            with firewalled_strix_sandbox(
                target_url="http://host.docker.internal:8077",
                poll_interval=0.01,
            ) as sandbox:
                # Wait for the watcher to firewall the discovered sandbox.
                deadline = time.monotonic() + 3.0
                while "sbx123" not in sandbox.firewalled and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertIn("sbx123", sandbox.firewalled)
                self.assertEqual(sandbox.target_port, 8077)
        # The sidecar applied the rules...
        self.assertTrue(any(c[1] == "run" and "--net=container:sbx123" in c for c in calls))
        # ...and teardown force-removed the firewalled sandbox.
        self.assertTrue(any(c[1] == "rm" and c[:3] == ["docker", "rm", "-f"]
                            and "sbx123" in c for c in calls))

    def test_no_sandbox_is_a_clean_noop(self) -> None:
        calls: list[list[str]] = []
        with patch("sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
                   side_effect=_fake_docker(calls, sandbox_id="")):
            with firewalled_strix_sandbox(
                target_url="http://host.docker.internal:8077",
                poll_interval=0.01,
            ) as sandbox:
                time.sleep(0.1)
                self.assertEqual(sandbox.firewalled, set())
        # Nothing was firewalled, so nothing is removed.
        self.assertFalse(any(c[1] == "run" for c in calls))
        self.assertFalse(any(c[1] == "rm" for c in calls))

    def test_watcher_errors_never_escape(self) -> None:
        # A docker failure in the watcher must not crash the run; the context
        # still enters and exits cleanly.
        def boom(command, **kwargs):
            return subprocess.CompletedProcess(command, 1, "", "nope")

        with patch("sechelix_runner.pentest.strix_sandbox_net.subprocess.run",
                   side_effect=boom):
            with firewalled_strix_sandbox(
                target_url="http://host.docker.internal:8077",
                poll_interval=0.01,
            ) as sandbox:
                time.sleep(0.05)
                self.assertEqual(sandbox.firewalled, set())


if __name__ == "__main__":
    unittest.main()
