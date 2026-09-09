"""The two plugin manifests describe one plugin and must not disagree.

`.claude-plugin/plugin.json` is what Claude Code reads. The root `plugin.json`
follows the agent-plugins.org convention that the Copilot CLI marketplace reads.
They exist because two ecosystems look in different places, not because there are
two plugins — so a version bump applied to one and not the other publishes a
release that advertises a version nobody can install.
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLAUDE = ROOT / ".claude-plugin" / "plugin.json"
AGENT = ROOT / "plugin.json"
ACTION = ROOT / "action.yml"


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

    #: Every top-level key Agent Plugins v1.0.0 permits. The published schema
    #: sets additionalProperties:false, so anything outside this set is a spec
    #: violation rather than a harmless extra. Client-specific data belongs
    #: under `extensions`, keyed by reverse-domain namespace.
    AGENT_PLUGINS_V1_KEYS = frozenset({
        "$schema", "name", "version", "description", "author",
        "homepage", "repository", "license", "keywords", "extensions",
    })

    def test_the_manifest_carries_no_field_the_spec_rejects(self):
        """Flagged by GitHub's awesome-copilot intake on a real submission.

        The manifest declared `skills` and `agents` pointing at the two
        directories. Discovery in v1.0.0 is by convention, not declaration, so
        those fields bought nothing and failed schema validation.
        """
        extra = sorted(set(self.agent) - self.AGENT_PLUGINS_V1_KEYS)
        self.assertEqual(extra, [], f"not part of Agent Plugins v1.0.0: {extra}")

    def test_the_conventional_directories_are_where_discovery_looks(self):
        """Removing the pointers only works if the convention holds."""
        for directory in ("skills", "agents"):
            with self.subTest(directory=directory):
                self.assertTrue((ROOT / directory).is_dir())
        self.assertTrue((ROOT / "skills" / "sechelix" / "SKILL.md").is_file())

    def test_the_root_manifest_does_not_reintroduce_the_packaging_bug(self):
        """A root SKILL.md packages the whole repository; plugin.json must not add one."""
        self.assertFalse((ROOT / "SKILL.md").exists())


class ActionMarketplaceMetadata(unittest.TestCase):
    """`action.yml` is a Marketplace listing, and Marketplace has hard limits.

    Found by GitHub rejecting the listing: "Description must be less than 125
    characters." The description was 188. Nothing about the action was wrong --
    the metadata simply could not be published, and there is no way to discover
    that from CI without asserting it.
    """

    #: GitHub Marketplace rejects a description of 125 characters or more.
    MAX_DESCRIPTION = 125

    @classmethod
    def setUpClass(cls):
        text = ACTION.read_text(encoding="utf-8")
        # A tiny reader rather than a yaml dependency: the runner has none, and
        # this test must not be the thing that introduces one.
        match = re.search(r'^description:\s*"([^"]*)"', text, re.M)
        assert match, "action.yml must declare a single-line quoted description"
        cls.description = match.group(1)
        cls.name = re.search(r'^name:\s*"([^"]*)"', text, re.M).group(1)
        cls.text = text

    def test_description_fits_the_marketplace_limit(self):
        self.assertLess(
            len(self.description), self.MAX_DESCRIPTION,
            f"Marketplace rejects >= {self.MAX_DESCRIPTION} chars; "
            f"description is {len(self.description)}",
        )

    def test_description_is_a_single_line(self):
        """A folded scalar hides its true length from a reader counting lines."""
        self.assertNotIn("\n", self.description)
        self.assertEqual(self.description, self.description.strip())

    def test_name_and_branding_are_present_and_valid(self):
        """Marketplace requires a name, and only accepts a fixed colour set."""
        self.assertTrue(self.name)
        colour = re.search(r"^\s*color:\s*(\S+)", self.text, re.M).group(1)
        self.assertIn(colour, {"white", "yellow", "blue", "green",
                               "orange", "red", "purple", "gray-dark"})
        # assertRegex does not take flags, and `^` without re.M only matches the
        # start of the whole file — so search explicitly.
        self.assertIsNotNone(re.search(r"^\s*icon:\s*\S+", self.text, re.M))

    def test_the_dropped_detail_still_lives_in_the_docs(self):
        """Shortening the description must not lose the semantics it carried."""
        docs = (ROOT / "docs" / "github-action.md").read_text(encoding="utf-8")
        for word in ("PASS_WITH_KNOWN_RISK", "BLOCKED", "INCOMPLETE"):
            with self.subTest(word=word):
                self.assertIn(word, docs)


if __name__ == "__main__":
    unittest.main()
