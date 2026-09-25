from __future__ import annotations

import unittest

from sechelix_runner.pentest.runtime_manifest import TOOLS, runtime_inventory
from sechelix_runner.sandbox import SandboxSpec


class SecurityRuntimeTests(unittest.TestCase):
    def test_static_security_tools_have_no_network(self) -> None:
        self.assertTrue(TOOLS)
        self.assertTrue(all(not tool.network for tool in TOOLS.values()))

    def test_runtime_inventory_is_pinned(self) -> None:
        for item in runtime_inventory():
            self.assertRegex(str(item["version"]), r"^\d+\.\d+\.\d+$")

    def test_default_sandbox_remains_fail_closed(self) -> None:
        spec = SandboxSpec(image="sechelix-security-runtime:v5")
        self.assertFalse(spec.network_enabled)
        self.assertFalse(spec.privileged)
        self.assertTrue(spec.read_only_root)
        self.assertTrue(spec.no_new_privileges)
        self.assertIn("ALL", spec.drop_capabilities)
        args = spec.docker_args()
        self.assertIn("--network=none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop=ALL", args)


if __name__ == "__main__":
    unittest.main()
