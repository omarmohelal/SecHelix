"""Sandbox execution tests.

The confinement tests below start real containers. They are skipped when no
container runtime is available, because STATIC mode never needs one and CI
should not fail for lacking something the product does not require.

What they demonstrate is that the policy in ``sandbox.py`` is not decoration:
the container really does refuse network, really is read-only outside the
workspace, and really cannot see the host filesystem.
"""

import tempfile
import unittest
from pathlib import Path

from sechelix_runner.sandbox import SandboxSpec
from sechelix_runner.sandbox_exec import (
    SandboxRefused,
    SandboxRunner,
    SandboxUnavailable,
    runtime_available,
)

DOCKER = runtime_available()
IMAGE = "python:3.12-slim"
requires_docker = unittest.skipUnless(DOCKER, "no container runtime available")


class CommandConstructionTests(unittest.TestCase):
    """These need no runtime: the command is built before anything starts."""

    def test_defaults_deny_the_network(self) -> None:
        command = SandboxRunner(SandboxSpec(image=IMAGE)).build_command(["true"])
        self.assertIn("--network=none", command)

    def test_defaults_drop_capabilities_and_privileges(self) -> None:
        command = SandboxRunner(SandboxSpec(image=IMAGE)).build_command(["true"])
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--security-opt=no-new-privileges", command)
        self.assertIn("--read-only", command)

    def test_resource_and_process_limits_are_applied(self) -> None:
        command = SandboxRunner(SandboxSpec(image=IMAGE)).build_command(["true"])
        self.assertIn("--pids-limit=256", command)
        self.assertTrue(any(a.startswith("--memory=") for a in command))
        self.assertTrue(any(a.startswith("--cpus=") for a in command))

    def test_container_does_not_run_as_root(self) -> None:
        command = SandboxRunner(SandboxSpec(image=IMAGE)).build_command(["true"])
        self.assertIn("--user", command)
        user = command[command.index("--user") + 1]
        self.assertRegex(user, r"^\d+:\d+$")
        self.assertFalse(user.startswith("0:"), "container must not run as root")

    def test_workspace_is_the_only_writable_mount(self) -> None:
        workspace = Path(tempfile.mkdtemp())
        command = SandboxRunner(SandboxSpec(image=IMAGE)).build_command(
            ["true"], workspace=workspace
        )
        writable = [a for a in command if a.startswith("--volume=") and a.endswith(":rw")]
        self.assertEqual(len(writable), 1)
        self.assertIn(str(workspace.resolve()), writable[0])

    def test_an_unsafe_spec_is_refused_before_anything_starts(self) -> None:
        for spec in (
            SandboxSpec(image=IMAGE, privileged=True),
            SandboxSpec(image=IMAGE, no_new_privileges=False),
            SandboxSpec(image=IMAGE, drop_capabilities=()),
        ):
            with self.subTest(spec=spec):
                with self.assertRaises(SandboxRefused):
                    SandboxRunner(spec).build_command(["true"])

    def test_missing_runtime_is_reported_not_crashed(self) -> None:
        runner = SandboxRunner(SandboxSpec(image=IMAGE), binary="definitely-not-docker-xyz")
        with self.assertRaises(SandboxUnavailable):
            runner.run(["true"])


@requires_docker
class RealConfinementTests(unittest.TestCase):
    """Start actual containers and check what they can and cannot do."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = SandboxRunner(SandboxSpec(image=IMAGE))

    def setUp(self) -> None:
        self.workspace = Path(tempfile.mkdtemp())

    def _python(self, code: str, timeout: float = 90.0):
        return self.runner.run(
            ["python", "-c", code], workspace=self.workspace, timeout=timeout
        )

    def test_workspace_write_is_allowed(self) -> None:
        result = self._python("open('/workspace/w.txt','w').write('x')")
        self.assertTrue(result.ok, result.stderr)
        self.assertTrue((self.workspace / "w.txt").exists())

    def test_network_egress_is_denied(self) -> None:
        result = self._python(
            "import socket; socket.create_connection(('1.1.1.1', 53), timeout=5)"
        )
        self.assertNotEqual(result.exit_code, 0)

    def test_dns_resolution_is_denied(self) -> None:
        result = self._python("import socket; socket.gethostbyname('example.com')")
        self.assertNotEqual(result.exit_code, 0)

    def test_host_filesystem_is_not_visible(self) -> None:
        result = self._python("import os; os.listdir('/host')")
        self.assertNotEqual(result.exit_code, 0)

    def test_root_filesystem_is_read_only(self) -> None:
        result = self._python("open('/etc/evil','w').write('x')")
        self.assertNotEqual(result.exit_code, 0)

    def test_writes_outside_the_workspace_are_denied(self) -> None:
        result = self._python("open('/usr/local/evil','w').write('x')")
        self.assertNotEqual(result.exit_code, 0)

    def test_tmp_is_writable_for_scratch_work(self) -> None:
        result = self._python("open('/tmp/t','w').write('x')")
        self.assertTrue(result.ok, result.stderr)

    def test_a_hanging_command_is_killed_by_the_timeout(self) -> None:
        result = self.runner.run(
            ["python", "-c", "import time; time.sleep(300)"],
            workspace=self.workspace,
            timeout=15,
        )
        self.assertTrue(result.timed_out)
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
