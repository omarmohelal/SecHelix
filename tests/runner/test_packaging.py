"""Guards on the distributable package.

The wheel is how most people will get the runner, so the properties that make it
trustworthy are asserted here rather than checked by hand at release time.
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PYPROJECT = ROOT / "pyproject.toml"
RELEASE_MARKER = ROOT / "runner-release.json"
PUBLISH_WORKFLOW = ROOT / ".github" / "workflows" / "publish-pypi.yml"


def pyproject_text() -> str:
    return PYPROJECT.read_text(encoding="utf-8")


def package_version() -> str:
    match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_text(), re.M)
    if not match:
        raise AssertionError("pyproject.toml does not declare a version")
    return match.group(1)


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

    def test_sdist_contains_every_wheel_input(self) -> None:
        """A wheel built from the sdist must not depend on files only present in
        the git checkout.

        Regression for the first PyPI publish attempt: the sdist omitted
        ``catalog/`` (and the other canonical wheel inputs), so Hatch could build
        the sdist but failed when it tried to build a wheel from that sdist.
        """
        text = pyproject_text()
        sdist = re.search(
            r"\[tool\.hatch\.build\.targets\.sdist\]\s*.*?include\s*=\s*\[(.*?)\]",
            text,
            re.M | re.S,
        )
        self.assertIsNotNone(sdist, "sdist include list not declared")
        body = sdist.group(1)
        for required in ("/sechelix_runner", "/sechelix_core", "/schemas", "/catalog"):
            self.assertIn(f'"{required}"', body, f"sdist omits wheel input {required}")

    def test_the_agent_skill_is_not_packaged(self) -> None:
        """The skill is distributed through the skills ecosystem, not pip."""
        match = re.search(r"^packages\s*=\s*\[(.*?)\]", pyproject_text(), re.M | re.S)
        self.assertNotIn("skills", match.group(1))

    def test_version_is_a_valid_release_identifier(self) -> None:
        self.assertRegex(package_version(), r"^\d+\.\d+\.\d+([ab]\d+|rc\d+)?$")

    def test_release_marker_matches_package_version(self) -> None:
        """Publishing is an explicit, reviewable repository change.

        A stale marker makes CI fail before a release can silently publish the
        wrong bytes. Updating the marker is the intentional release trigger.
        """
        self.assertTrue(RELEASE_MARKER.is_file())
        marker = json.loads(RELEASE_MARKER.read_text(encoding="utf-8"))
        self.assertIs(marker.get("publish"), True)
        self.assertEqual(marker.get("version"), package_version())

    def test_publish_workflow_tracks_the_release_marker(self) -> None:
        workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("runner-release.json", workflow)
        self.assertIn("id-token: write", workflow)
        self.assertIn("environment:\n      name: pypi", workflow)

    def test_readme_referenced_by_pyproject_exists(self) -> None:
        match = re.search(r'^readme\s*=\s*"([^"]+)"', pyproject_text(), re.M)
        self.assertTrue((ROOT / match.group(1)).is_file())

    def test_build_artifacts_are_gitignored(self) -> None:
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for pattern in ("/dist/", "/build/", "*.egg-info/"):
            self.assertIn(pattern, ignored)


if __name__ == "__main__":
    unittest.main()
