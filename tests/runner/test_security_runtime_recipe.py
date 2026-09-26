from __future__ import annotations

import re
import unittest
from pathlib import Path

from sechelix_runner.pentest.runtime_manifest import TOOLS


class SecurityRuntimeRecipeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.path = Path("docker/security-runtime/Dockerfile")
        cls.dockerfile = cls.path.read_text(encoding="utf-8")

    def test_every_from_reference_is_digest_pinned(self) -> None:
        refs = re.findall(r"^FROM\s+(\S+)", self.dockerfile, flags=re.MULTILINE)
        self.assertGreaterEqual(len(refs), 3)
        for ref in refs:
            self.assertRegex(ref, r"@sha256:[0-9a-f]{64}$")

    def test_declared_tool_versions_match_runtime_inventory(self) -> None:
        expected = {
            "SEMGREP_VERSION": TOOLS["semgrep"].version,
            "PIP_AUDIT_VERSION": TOOLS["dependency-audit"].version,
            "TRIVY_VERSION": TOOLS["trivy"].version,
            "GITLEAKS_VERSION": TOOLS["gitleaks"].version,
        }
        for name, version in expected.items():
            self.assertIn(f"ARG {name}={version}", self.dockerfile)

    def test_recipe_never_adds_sudo_or_a_generic_shell_entrypoint(self) -> None:
        lowered = self.dockerfile.lower()
        self.assertNotIn("sudo", lowered)
        self.assertNotRegex(lowered, r"entrypoint\s*\[?\s*[\"']?(bash|sh)")
        self.assertIn("USER sechelix", self.dockerfile)

    def test_recipe_does_not_fetch_runtime_databases(self) -> None:
        # Runtime DBs/advisory data need a separately pinned/operator-controlled
        # source. A Docker build that silently downloads "latest" data would
        # defeat the otherwise immutable recipe.
        lowered = self.dockerfile.lower()
        self.assertNotIn("--download-db-only", lowered)
        self.assertNotIn("trivy-db", lowered)
        self.assertNotIn("curl ", lowered)
        self.assertNotIn("wget ", lowered)


if __name__ == "__main__":
    unittest.main()
