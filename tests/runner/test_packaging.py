"""Guards on the distributable package.

The wheel is how most people will get the runner, so the properties that make it
trustworthy are asserted here rather than checked by hand at release time.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"


def pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


class PackageMetadataTests(unittest.TestCase):
    def test_pyproject_exists(self) -> None:
        self.assertTrue(PYPROJECT.is_file())

    def test_package_declares_no_runtime_dependencies(self) -> None:
        """A security tool that drags in a dependency tree widens the attack
        surface of the thing it was installed to protect."""
        match = re.search(r"^dependencies\s*=\s*\[(.*?)\]", pyproject_text(), re.M | re.S)
        self.assertIsNotNone(match, "dependencies not declared")
        self.assertEqual(match.group(1).strip(), "")

    def test_console_script_points_at_the_cli(self) -> None:
        self.assertIn('sechelix = "sechelix_runner.cli:main"', pyproject_text())

    def test_entry_point_target_is_callable(self) -> None:
        from sechelix_runner.cli import main

        self.assertTrue(callable(main))

    def test_licence_is_declared(self) -> None:
        self.assertIn('license = "Apache-2.0"', pyproject_text())

    def test_contracts_ship_with_the_runner(self) -> None:
        """Without these, `doctor` reports core_contracts=False on every install
        and 'the runner consumes the contracts' is true only for git clones."""
        text = pyproject_text()
        self.assertIn('packages = ["sechelix_runner", "sechelix_core"]', text)
        self.assertIn("schemas", text)
        self.assertIn("catalog", text)

    def test_the_agent_skill_is_not_packaged(self) -> None:
        """The skill is distributed through the skills ecosystem, not pip."""
        match = re.search(r"^packages\s*=\s*\[(.*?)\]", pyproject_text(), re.M | re.S)
        self.assertNotIn("skills", match.group(1))

    def test_version_is_a_valid_release_identifier(self) -> None:
        match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_text(), re.M)
        self.assertRegex(match.group(1), r"^\d+\.\d+\.\d+([ab]\d+|rc\d+)?$")

    def test_readme_referenced_by_pyproject_exists(self) -> None:
        match = re.search(r'^readme\s*=\s*"([^"]+)"', pyproject_text(), re.M)
        self.assertTrue((ROOT / match.group(1)).is_file())

    def test_build_artifacts_are_gitignored(self) -> None:
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for pattern in ("/dist/", "/build/", "*.egg-info/"):
            self.assertIn(pattern, ignored)


if __name__ == "__main__":
    unittest.main()
