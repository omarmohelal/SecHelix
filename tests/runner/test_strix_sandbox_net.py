from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sechelix_runner.pentest import strix_sandbox_net as net
from sechelix_runner.pentest.strix_sandbox_net import (
    ContainmentFailed,
    SandboxNetworkError,
    _apply_egress_firewall,
    _firewall_script,
    _reap_stale_claims,
    _release_claim,
    _running_sandbox_ids,
    _sandbox_host_gateways,
    _try_claim,
    _valid_ip,
    _verify_containment,
    ensure_firewall_helper_image,
    firewalled_strix_sandbox,
    isolation_requested,
)

GW4 = "192.168.65.254"
TARGET_PORT = 8077


def _url_host_port(command: list[str]) -> tuple[str, int]:
    for arg in command:
        if arg.startswith("http://"):
            rest = arg[len("http://"):].split("/", 1)[0]
            host, _, port = rest.partition(":")
            return host, int(port or "80")
    raise AssertionError(f"no url in {command}")


class FakeDocker:
    """A thread-safe ``subprocess.run`` stand-in modelling the docker calls."""

    def __init__(
        self,
        *,
        sandbox_ids: list[str] | None = None,
        image_present: bool = True,
        gw4: str = GW4,
        gw6: str = "",
        probe_rc=None,
    ) -> None:
        self.sandbox_ids = sandbox_ids if sandbox_ids is not None else []
        self.image_present = image_present
        self.gw4 = gw4
        self.gw6 = gw6
        self.probe_rc = probe_rc or self._default_probe
        self.calls: list[list[str]] = []
        self.removed: list[str] = []
        self._lock = threading.Lock()

    def _default_probe(self, host: str, port: int) -> int:
        # Good containment: target reachable, everything else dropped.
        if host == self.gw4 and port == TARGET_PORT:
            return 0
        return 28

    def __call__(self, command, **kwargs):
        if kwargs.get("shell") is not False:
            raise AssertionError("docker must never run through a shell")
        with self._lock:
            self.calls.append(list(command))
            verb = command[1] if len(command) > 1 else ""
            rc, out = 0, "ok"
            if verb == "image":  # image inspect
                rc = 0 if self.image_present else 1
            elif verb == "build":
                self.image_present = True
            elif verb == "ps":
                rows = ["deadbeef alpine:3.20"]
                for sid in self.sandbox_ids:
                    rows.insert(0, f"{sid} ghcr.io/usestrix/strix-sandbox:1.3.0")
                out = "\n".join(rows)
            elif verb == "rm":
                self.removed.append(command[-1])
            elif verb == "exec" and "getent" in command:
                out = (f"{self.gw4} host.docker.internal" if "ahostsv4" in command
                       else (f"{self.gw6} host.docker.internal" if self.gw6 else ""))
            elif verb == "exec" and "curl" in command:
                host, port = _url_host_port(command)
                rc = self.probe_rc(host, port)
                out = "000" if rc else "200"
        return subprocess.CompletedProcess(command, rc, out, "")


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

    def test_firewall_script_is_default_drop_bounded_egress(self) -> None:
        script = _firewall_script(ipv4_gw=GW4, ipv6_gw=None, target_port=TARGET_PORT)
        # Caido + DNS survive: loopback and established are accepted...
        self.assertIn("iptables -A OUTPUT -o lo -j ACCEPT", script)
        self.assertIn("ESTABLISHED,RELATED -j ACCEPT", script)
        self.assertIn(f"-d {net._EMBEDDED_DNS} --dport 53 -j ACCEPT", script)
        # ...only the target port on the gateway is allowed...
        self.assertIn(f"-d {GW4} -p tcp --dport {TARGET_PORT} -j ACCEPT", script)
        # ...and the default is DROP (the real boundary), both as a catch-all
        # rule and as chain policy.
        self.assertIn("iptables -A OUTPUT -j DROP", script)
        self.assertIn("iptables -P OUTPUT DROP", script)
        # Ordering: every ACCEPT precedes the catch-all DROP.
        drop = script.index("iptables -A OUTPUT -j DROP")
        self.assertLess(script.index("-o lo -j ACCEPT"), drop)
        self.assertLess(script.index(f"--dport {TARGET_PORT} -j ACCEPT"), drop)
        self.assertNotIn("ip6tables", script)  # no v6 gateway given
        self.assertNotIn("apk add", script)  # no runtime package download

    def test_firewall_script_mirrors_ipv6(self) -> None:
        script = _firewall_script(ipv4_gw=GW4, ipv6_gw="fd00::254", target_port=443)
        self.assertIn("ip6tables -A OUTPUT -o lo -j ACCEPT", script)
        self.assertIn("ip6tables -A OUTPUT -d fd00::254 -p tcp --dport 443 -j ACCEPT", script)
        self.assertIn("ip6tables -P OUTPUT DROP", script)

    def test_firewall_script_rejects_bad_port_and_no_gateway(self) -> None:
        with self.assertRaises(SandboxNetworkError):
            _firewall_script(ipv4_gw=GW4, ipv6_gw=None, target_port=0)
        with self.assertRaises(SandboxNetworkError):
            _firewall_script(ipv4_gw=None, ipv6_gw=None, target_port=8077)

    def test_running_sandbox_ids_matches_image_name_not_tagless_ancestor(self) -> None:
        fake = FakeDocker(sandbox_ids=["sbx123"])
        with patch.object(net.subprocess, "run", side_effect=fake):
            ids = _running_sandbox_ids(docker="docker")
        self.assertEqual(ids, ["sbx123"])  # the alpine row is ignored
        self.assertNotIn("ancestor=ghcr.io/usestrix/strix-sandbox", fake.calls[0])
        self.assertIn("{{.ID}} {{.Image}}", fake.calls[0])

    def test_sandbox_host_gateways_parses_getent(self) -> None:
        fake = FakeDocker(gw4=GW4, gw6="fd00::254")
        with patch.object(net.subprocess, "run", side_effect=fake):
            v4, v6 = _sandbox_host_gateways("sbx123", docker="docker")
        self.assertEqual(v4, GW4)
        self.assertEqual(v6, "fd00::254")

    def test_apply_egress_firewall_runs_pinned_netns_sidecar(self) -> None:
        fake = FakeDocker()
        with patch.object(net.subprocess, "run", side_effect=fake):
            _apply_egress_firewall(
                "sbx123", ipv4_gw=GW4, ipv6_gw=None,
                target_port=TARGET_PORT, docker="docker",
            )
        run = next(c for c in fake.calls if c[1] == "run")
        self.assertIn("--net=container:sbx123", run)
        self.assertIn("NET_ADMIN", run)
        self.assertIn(net._FW_IMAGE, run)  # the pinned prebuilt image
        self.assertEqual(run[-2], "-c")
        self.assertIn("-j DROP", run[-1])


class HelperImage(unittest.TestCase):
    def test_present_image_is_not_rebuilt(self) -> None:
        fake = FakeDocker(image_present=True)
        with patch.object(net.subprocess, "run", side_effect=fake):
            ensure_firewall_helper_image(docker="docker")
        self.assertFalse(any(c[1] == "build" for c in fake.calls))

    def test_absent_image_is_built_once(self) -> None:
        fake = FakeDocker(image_present=False)
        with patch.object(net.subprocess, "run", side_effect=fake):
            ensure_firewall_helper_image(docker="docker")
        self.assertTrue(any(c[1] == "build" and net._FW_IMAGE in c for c in fake.calls))


class ClaimRegistry(unittest.TestCase):
    def test_claim_is_exclusive_and_releasable(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            reg = Path(d)
            a = f"{os.getpid()}:aaa"
            b = f"{os.getpid()}:bbb"
            self.assertTrue(_try_claim("cid1", owner=a, registry_dir=reg))
            # A second owner cannot claim the same (live) container.
            self.assertFalse(_try_claim("cid1", owner=b, registry_dir=reg))
            # Releasing by the owner frees it for another claim.
            _release_claim("cid1", owner=a, registry_dir=reg)
            self.assertTrue(_try_claim("cid1", owner=b, registry_dir=reg))

    def test_stale_claim_from_dead_owner_is_reclaimable(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            reg = Path(d)
            (reg / "cid1").write_text("999999:dead", "utf-8")
            with patch.object(net, "_pid_alive", return_value=False):
                self.assertTrue(_try_claim("cid1", owner=f"{os.getpid()}:new", registry_dir=reg))

    def test_reaper_removes_dead_owner_container_but_keeps_live(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            reg = Path(d)
            (reg / "deadcid").write_text("999999:x", "utf-8")
            (reg / "livecid").write_text(f"{os.getpid()}:y", "utf-8")
            fake = FakeDocker()

            def alive(pid: int) -> bool:
                return pid == os.getpid()

            with patch.object(net.subprocess, "run", side_effect=fake), \
                 patch.object(net, "_pid_alive", side_effect=alive):
                _reap_stale_claims(docker="docker", registry_dir=reg)
            self.assertIn("deadcid", fake.removed)
            self.assertNotIn("livecid", fake.removed)
            self.assertFalse((reg / "deadcid").exists())
            self.assertTrue((reg / "livecid").exists())  # live run untouched


class Verification(unittest.TestCase):
    def test_bounded_egress_passes_verification(self) -> None:
        fake = FakeDocker()
        with patch.object(net.subprocess, "run", side_effect=fake):
            _verify_containment("sbx", ipv4_gw=GW4, target_port=TARGET_PORT, docker="docker")

    def test_unreachable_target_fails(self) -> None:
        def probe(host, port):  # target times out too
            return 28
        fake = FakeDocker(probe_rc=probe)
        with patch.object(net.subprocess, "run", side_effect=fake):
            with self.assertRaises(ContainmentFailed):
                _verify_containment("sbx", ipv4_gw=GW4, target_port=TARGET_PORT, docker="docker")

    def test_sibling_port_reaching_host_fails(self) -> None:
        def probe(host, port):
            if host == GW4 and port == TARGET_PORT:
                return 0
            if host == GW4:
                return 7  # refused -> packet reached the host: NOT contained
            return 28
        fake = FakeDocker(probe_rc=probe)
        with patch.object(net.subprocess, "run", side_effect=fake):
            with self.assertRaises(ContainmentFailed):
                _verify_containment("sbx", ipv4_gw=GW4, target_port=TARGET_PORT, docker="docker")


class Lifecycle(unittest.TestCase):
    def _wait(self, cond, timeout=4.0):
        deadline = time.monotonic() + timeout
        while not cond() and time.monotonic() < deadline:
            time.sleep(0.02)

    def test_watcher_contains_new_sandbox_then_teardown_removes_only_owned(self) -> None:
        fake = FakeDocker(sandbox_ids=[])  # none at baseline
        with tempfile.TemporaryDirectory() as d:
            with patch.object(net.subprocess, "run", side_effect=fake):
                with firewalled_strix_sandbox(
                    target_url=f"http://host.docker.internal:{TARGET_PORT}",
                    poll_interval=0.01, registry_dir=d,
                ) as state:
                    fake.sandbox_ids.append("sbx123")  # appears after baseline
                    self._wait(lambda: state.contained.is_set())
                    self.assertTrue(state.contained.is_set())
                    self.assertIn("sbx123", state.firewalled)
                    self.assertIsNone(state.failure)
            # pause -> firewall(run) -> unpause happened, in that order.
            verbs = [c[1] for c in fake.calls if c[1] in {"pause", "run", "unpause"}]
            self.assertEqual(verbs[:3], ["pause", "run", "unpause"])
            # teardown force-removed the owned sandbox.
            self.assertIn("sbx123", fake.removed)

    def test_preexisting_sandbox_is_baselined_and_never_touched(self) -> None:
        fake = FakeDocker(sandbox_ids=["pre1"])  # already running at entry
        with tempfile.TemporaryDirectory() as d:
            with patch.object(net.subprocess, "run", side_effect=fake):
                with firewalled_strix_sandbox(
                    target_url=f"http://host.docker.internal:{TARGET_PORT}",
                    poll_interval=0.01, registry_dir=d,
                ) as state:
                    time.sleep(0.1)
                    self.assertNotIn("pre1", state.firewalled)
            self.assertNotIn("pre1", fake.removed)  # another scan's sandbox: untouched
            self.assertFalse(any(c[1] == "pause" for c in fake.calls))

    def test_sandbox_claimed_by_another_run_is_skipped(self) -> None:
        fake = FakeDocker(sandbox_ids=[])
        with tempfile.TemporaryDirectory() as d:
            # A concurrent, live run already owns sbx123.
            Path(d, "sbx123").write_text(f"{os.getpid()}:other", "utf-8")
            with patch.object(net.subprocess, "run", side_effect=fake):
                with firewalled_strix_sandbox(
                    target_url=f"http://host.docker.internal:{TARGET_PORT}",
                    poll_interval=0.01, registry_dir=d,
                ) as state:
                    fake.sandbox_ids.append("sbx123")
                    time.sleep(0.15)
                    self.assertNotIn("sbx123", state.firewalled)
            self.assertNotIn("sbx123", fake.removed)  # never remove a foreign claim

    def test_containment_failure_kills_sandbox_and_fails_closed(self) -> None:
        def probe(host, port):  # target unreachable -> verification fails
            return 28
        fake = FakeDocker(sandbox_ids=[], probe_rc=probe)
        with tempfile.TemporaryDirectory() as d:
            with patch.object(net.subprocess, "run", side_effect=fake):
                with firewalled_strix_sandbox(
                    target_url=f"http://host.docker.internal:{TARGET_PORT}",
                    poll_interval=0.01, registry_dir=d,
                ) as state:
                    fake.sandbox_ids.append("sbx123")
                    self._wait(lambda: state.failure is not None)
                    self.assertIsNotNone(state.failure)
                    self.assertFalse(state.contained.is_set())
            self.assertIn("sbx123", fake.removed)  # killed to drop Strix's tools

    def test_docker_unavailable_fails_closed(self) -> None:
        def boom(command, **kwargs):
            if command[1] == "ps":
                raise net.SandboxNetworkError("docker down")
            return subprocess.CompletedProcess(command, 0, "ok", "")
        with tempfile.TemporaryDirectory() as d:
            # image inspect ok, baseline ps raises -> enter fails closed.
            with patch.object(net.subprocess, "run", side_effect=boom):
                with self.assertRaises(SandboxNetworkError):
                    with firewalled_strix_sandbox(
                        target_url=f"http://host.docker.internal:{TARGET_PORT}",
                        poll_interval=0.01, registry_dir=d,
                    ):
                        pass

    def test_no_sandbox_is_a_clean_noop(self) -> None:
        fake = FakeDocker(sandbox_ids=[])
        with tempfile.TemporaryDirectory() as d:
            with patch.object(net.subprocess, "run", side_effect=fake):
                with firewalled_strix_sandbox(
                    target_url=f"http://host.docker.internal:{TARGET_PORT}",
                    poll_interval=0.01, registry_dir=d,
                ) as state:
                    time.sleep(0.1)
                    self.assertEqual(state.firewalled, set())
                    self.assertFalse(state.contained.is_set())
            self.assertFalse(any(c[1] in {"pause", "run"} for c in fake.calls))
            self.assertEqual(fake.removed, [])


if __name__ == "__main__":
    unittest.main()
