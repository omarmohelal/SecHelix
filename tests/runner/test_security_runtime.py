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
PY_INPUT_PATH = RUNTIME_DIR / "python-tools.in"
PY_LOCK_PATH = RUNTIME_DIR / "python-tools.lock"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PY_REQUIREMENT = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)\s*\\?$")


class SecurityRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
        self.dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
        self.python_input = PY_INPUT_PATH.read_text(encoding="utf-8")
        self.python_lock = PY_LOCK_PATH.read_text(encoding="utf-8")

    def test_static_security_tools_have_no_network(self) -> None:
        self.assertTrue(TOOLS)
        self.assertTrue(all(not tool.network for tool in TOOLS.values()))

    def test_runtime_inventory_is_version_pinned_and_truthful_about_provenance(self) -> None:
        inventory = {str(item["name"]): item for item in runtime_inventory()}
        for item in inventory.values():
            self.assertRegex(str(item["version"]), r"^\d+\.\d+\.\d+$")
            self.assertIn(
                item["pinning"],
                {"version-only", "sha256-release-asset", "sha256-python-lock"},
            )

        for name in ("gitleaks", "trivy"):
            self.assertEqual(inventory[name]["pinning"], "sha256-release-asset")
            digests = inventory[name]["artifact_sha256_by_arch"]
            self.assertEqual(set(digests), {"amd64", "arm64"})
            self.assertTrue(all(SHA256.fullmatch(value) for value in digests.values()))

        for name in ("semgrep", "dependency-audit"):
            self.assertEqual(inventory[name]["pinning"], "sha256-python-lock")
            self.assertEqual(inventory[name]["dependency_lock"], "python-tools.lock")

    def test_runtime_lock_matches_manifest_versions_and_binary_hashes(self) -> None:
        self.assertEqual(
            self.lock["schema_version"],
            "sechelix-security-runtime-lock/v2",
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

        python_lock = self.lock["python_dependency_lock"]
        self.assertEqual(python_lock["input"], "python-tools.in")
        self.assertEqual(python_lock["requirements"], "python-tools.lock")
        self.assertEqual(python_lock["generator"], "pip-tools==7.6.1")
        self.assertEqual(python_lock["python"], "3.12.11")
        self.assertEqual(python_lock["install_mode"], "pip --require-hashes")

    def test_python_runtime_lock_pins_transitive_versions_and_hashes(self) -> None:
        input_roots: dict[str, str] = {}
        for raw in self.python_input.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = PY_REQUIREMENT.fullmatch(line)
            self.assertIsNotNone(match, f"direct runtime requirement is not exact: {line}")
            assert match is not None
            input_roots[match.group(1).lower()] = match.group(2)

        lines = self.python_lock.splitlines()
        package_indexes: list[tuple[int, str, str]] = []
        for index, raw in enumerate(lines):
            if raw.startswith((" ", "#")) or not raw.strip():
                continue
            match = PY_REQUIREMENT.fullmatch(raw.strip())
            self.assertIsNotNone(match, f"locked requirement is not exact: {raw}")
            assert match is not None
            package_indexes.append((index, match.group(1).lower(), match.group(2)))

        self.assertGreater(len(package_indexes), 20, "expected a real transitive dependency graph")
        locked_versions = {name: version for _index, name, version in package_indexes}
        self.assertEqual(locked_versions["semgrep"], TOOLS["semgrep"].version)
        self.assertEqual(
            locked_versions["pip-audit"],
            TOOLS["dependency-audit"].version,
        )
        self.assertIn("pip", locked_versions)

        for offset, (index, name, _version) in enumerate(package_indexes):
            stop = (
                package_indexes[offset + 1][0]
                if offset + 1 < len(package_indexes)
                else len(lines)
            )
            stanza = "\n".join(lines[index:stop])
            hashes = re.findall(r"--hash=sha256:([0-9a-f]{64})", stanza)
            self.assertTrue(hashes, f"{name} has no SHA-256 artifact hash")

        self.assertEqual(input_roots["semgrep"], TOOLS["semgrep"].version)
        self.assertEqual(
            input_roots["pip-audit"],
            TOOLS["dependency-audit"].version,
        )
        active_lines = [
            line.strip()
            for line in lines
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertFalse(any(line.startswith("--index-url") for line in active_lines))
        self.assertFalse(any(line.startswith("--trusted-host") for line in active_lines))

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

        self.assertIn("COPY python-tools.lock /tmp/python-tools.lock", self.dockerfile)
        self.assertIn("--require-hashes", self.dockerfile)
        self.assertIn("-r /tmp/python-tools.lock", self.dockerfile)
        self.assertNotIn('"semgrep==${SEMGREP_VERSION}"', self.dockerfile)
        self.assertNotIn('"pip-audit==${PIP_AUDIT_VERSION}"', self.dockerfile)

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
