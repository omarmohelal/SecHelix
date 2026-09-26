from __future__ import annotations

import unittest

from sechelix_runner.pentest.runtime_manifest import (
    SECURITY_RUNTIME_PARENT_IMAGES,
    TOOLS,
    is_digest_pinned_image,
    runtime_build_manifest,
    runtime_inventory,
)
from sechelix_runner.sandbox import SandboxSpec


class SecurityRuntimeTests(unittest.TestCase):
    def test_static_security_tools_have_no_network(self) -> None:
        self.assertTrue(TOOLS)
        self.assertTrue(all(not tool.network for tool in TOOLS.values()))

    def test_runtime_inventory_is_pinned(self) -> None:
        for item in runtime_inventory():
            self.assertRegex(str(item["version"]), r"^\d+\.\d+\.\d+$")

    def test_runtime_parent_images_are_immutable_digest_references(self) -> None:
        self.assertTrue(SECURITY_RUNTIME_PARENT_IMAGES)
        self.assertTrue(
            all(is_digest_pinned_image(ref) for ref in SECURITY_RUNTIME_PARENT_IMAGES.values())
        )
        self.assertFalse(is_digest_pinned_image("python:3.12-slim"))
        self.assertFalse(is_digest_pinned_image("ghcr.io/example/tool:latest"))

    def test_build_manifest_does_not_claim_an_unpublished_runtime_digest(self) -> None:
        manifest = runtime_build_manifest()
        self.assertEqual(manifest["published_runtime_image"], "NOT_PUBLISHED")
        self.assertEqual(manifest["runtime_network_default"], "DENY")
        self.assertFalse(manifest["generic_agent_shell_exposed"])
        self.assertTrue(manifest["limitations"])

    def test_security_runtime_requires_immutable_image_when_enabled(self) -> None:
        mutable = SandboxSpec(
            image="sechelix-security-runtime:v5",
            require_pinned_image=True,
        )
        self.assertTrue(any("pinned by sha256" in item for item in mutable.validate()))

        pinned = SandboxSpec(
            image="registry.example/sechelix-security-runtime@sha256:" + "a" * 64,
            require_pinned_image=True,
        )
        self.assertEqual(pinned.validate(), [])

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
