"""The two plugin manifests describe one plugin and must not disagree.

`.claude-plugin/plugin.json` is what Claude Code reads. The root `plugin.json`
follows the agent-plugins.org convention that the Copilot CLI marketplace reads.
They exist because two ecosystems look in different places, not because there are
two plugins — so a version bump applied to one and not the other publishes a
release that advertises a version nobody can install.
"""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAUDE = ROOT / ".claude-plugin" / "plugin.json"
AGENT = ROOT / "plugin.json"


class ManifestAgreementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.claude = json.loads(CLAUDE.read_text(encoding="utf-8"))
        cls.agent = json.loads(AGENT.read_text(encoding="utf-8"))

    def test_both_manifests_exist(self):
        self.assertTrue(CLAUDE.is_file())
        self.assertTrue(AGENT.is_file())

    def test_versions_agree(self):
        self.assertEqual(self.claude["version"], self.agent["version"])

    def test_identity_fields_agree(self):
        for field in ("name", "license", "repository", "homepage"):
            with self.subTest(field=field):
                self.assertEqual(self.claude.get(field), self.agent.get(field))

    def test_the_version_matches_the_changelog_and_citation(self):
        version = self.agent["version"]
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"## [{version}]", changelog)
        citation = (ROOT / "CITATION.cff").read_text(encoding="utf-8")
        self.assertIn(f"version: {version}", citation)

    def test_release_notes_exist_for_this_version(self):
        self.assertTrue((ROOT / "docs" / "releases" / f"{self.agent['version']}.md").is_file())

    def test_content_pointers_resolve(self):
        """A manifest naming a directory that is not there installs nothing."""
        for key in ("skills", "agents"):
            target = self.agent.get(key)
            if target:
                with self.subTest(key=key):
                    self.assertTrue((ROOT / target.strip("./")).is_dir(), target)

    def test_the_root_manifest_does_not_reintroduce_the_packaging_bug(self):
        """A root SKILL.md packages the whole repository; plugin.json must not add one."""
        self.assertFalse((ROOT / "SKILL.md").exists())


if __name__ == "__main__":
    unittest.main()
