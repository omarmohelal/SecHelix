from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

from sechelix_runner.pentest.runtime_manifest import (
    SECURITY_RUNTIME_BASE_IMAGE,
    TOOLS,
    runtime_inventory,
)
from sechelix_runner.sandbox import SandboxSpec


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DIR = ROOT / "containers" / "security-runtime"
LOCK_PATH = RUNTIME_DIR / "runtime-lock.json"
DOCKERFILE_PATH = RUNTIME_DIR / "Dockerfile"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class SecurityRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        self.dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")

    def test_static_security_tools_have_no_network(self) -> None:
        self.assertTrue(TOOLS)
        self.assertTrue(all(not tool.network for tool in TOOLS.values()))

    def test_runtime_inventory_is_version_pinned_and_truthful_about_provenance(self) -> None:
        inventory = {str(item["name"]): item for item in runtime_inventory()}
        for item in inventory.values():
            self.assertRegex(str(item["version"]), r"^\d+\.\d+\.\d+$")
            self.assertIn(
                item["pinning"],
                {"version-only", "sha256-release-asset"},
            )

        for name in ("gitleaks", "trivy"):
            self.assertEqual(inventory[name]["pinning"], "sha256-release-asset")
            digests = inventory[name]["artifact_sha256_by_arch"]
            self.assertEqual(set(digests), {"amd64", "arm64"})
            self.assertTrue(all(SHA256.fullmatch(value) for value in digests.values()))

        # Python package versions are exact, but transitive wheel hashes have
        # not yet been locked. Keep the manifest honest rather than overstating
        # artifact-level reproducibility.
        self.assertEqual(inventory["semgrep"]["pinning"], "version-only")
        self.assertEqual(inventory["dependency-audit"]["pinning"], "version-only")

    def test_runtime_lock_matches_manifest_versions_and_binary_hashes(self) -> None:
        self.assertEqual(
            self.lock["schema_version"],
            "sechelix-security-runtime-lock/v1",
        )
        self.assertEqual(
            self.lock["base_image"]["reference"],
            SECURITY_RUNTIME_BASE_IMAGE,
        )
        self.assertTrue(SHA256.fullmatch(self.lock["base_image"]["index_sha256"]))

        self.assertEqual(
            self.lock["python_tools"]["semgrep"]["version"],
            TOOLS["semgrep"].version,
        )
        self.assertEqual(
            self.lock["python_tools"]["dependency-audit"]["version"],
            TOOLS["dependency-audit"].version,
        )

        for name in ("gitleaks", "trivy"):
            tool = TOOLS[name]
            locked = self.lock["binary_tools"][name]
            self.assertEqual(locked["version"], tool.version)
            manifest_digests = dict(tool.artifact_sha256_by_arch)
            for arch in ("amd64", "arm64"):
                asset = locked["assets"][arch]
                self.assertRegex(asset["filename"], re.escape(tool.version))
                self.assertTrue(SHA256.fullmatch(asset["sha256"]))
                self.assertEqual(asset["sha256"], manifest_digests[arch])

    def test_dockerfile_pins_base_and_verifies_binary_archives_before_extraction(self) -> None:
        self.assertEqual(
            self.dockerfile.count(f"FROM {SECURITY_RUNTIME_BASE_IMAGE}"),
            2,
        )
        self.assertGreaterEqual(self.dockerfile.count("sha256sum -c -"), 2)

        for name in ("gitleaks", "trivy"):
            locked = self.lock["binary_tools"][name]
            self.assertIn(f"{name.upper().replace('-', '_')}_VERSION={locked['version']}", self.dockerfile)
            for arch in ("amd64", "arm64"):
                asset = locked["assets"][arch]
                self.assertIn(asset["filename"].replace(locked["version"], "${" + name.upper().replace("-", "_") + "_VERSION}"), self.dockerfile)
                self.assertIn(asset["sha256"], self.dockerfile)

        self.assertNotIn("TRIVY_VERSION=0.66.0", self.dockerfile)

    def test_final_runtime_stage_does_not_keep_download_toolchain(self) -> None:
        final_stage = self.dockerfile.rsplit(
            f"FROM {SECURITY_RUNTIME_BASE_IMAGE}",
            1,
        )[1]
        self.assertNotIn("apt-get", final_stage)
        self.assertNotIn("curl ", final_stage)
        self.assertNotIn("tar ", final_stage)
        self.assertIn("USER 10001:10001", final_stage)

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
