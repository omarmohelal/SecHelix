"""The curated public-directory edition stays small, runtime-free and in step with the canonical contracts.

Each negative test copies the real package, breaks one property, and asserts the gate notices. A
gate that only ever passes on the current tree proves nothing about the next change.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import validate_distribution as gate


class CuratedDistributionTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.package = Path(self._tmp.name) / "awesome-copilot"
        shutil.copytree(gate.PACKAGE, self.package)
        self.skill = gate.discovered_skills(self.package)[0]
        self.references = self.skill.parent / "references"

    def tearDown(self):
        self._tmp.cleanup()

    def problems(self):
        return gate.validate(self.package)

    def assertFlags(self, fragment):
        problems = self.problems()
        self.assertTrue(any(fragment in p for p in problems), f"{fragment!r} not in {problems}")

    def edit_manifest(self, **changes):
        path = self.package / "plugin.json"
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest.update(changes)
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def append(self, path, text):
        path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")

    # -- the shipped package ------------------------------------------------------------

    def test_the_shipped_package_passes(self):
        self.assertEqual(gate.validate(), [])

    def test_the_budgets_meet_the_directory_feedback(self):
        self.assertLessEqual(gate.MAX_SKILL_LINES, 250)
        self.assertLessEqual(gate.MAX_SUPPORT_FILES, 8)

    # -- size ----------------------------------------------------------------------------

    def test_skill_line_budget(self):
        self.append(self.skill, "\n" * (gate.MAX_SKILL_LINES + 1))
        self.assertFlags("lines; the budget is")

    def test_supporting_file_budget(self):
        for n in range(gate.MAX_SUPPORT_FILES):
            name = f"extra-{n}.md"
            (self.references / name).write_text("# extra\n", encoding="utf-8")
            self.append(self.skill, f"\n- `references/{name}`\n")
        self.assertFlags("supporting files; the budget is")

    def test_code_files_are_not_shipped(self):
        (self.references / "helper.py").write_text("print('x')\n", encoding="utf-8")
        self.assertFlags("is not Markdown")

    # -- structure -----------------------------------------------------------------------

    def test_referenced_file_must_exist(self):
        self.append(self.skill, "\nLoad `references/missing.md`.\n")
        self.assertFlags("references/missing.md is referenced but not shipped")

    def test_shipped_file_must_be_referenced(self):
        (self.references / "orphan.md").write_text("# orphan\n", encoding="utf-8")
        self.assertFlags("references/orphan.md is shipped but SKILL.md never")

    def test_frontmatter_name_matches_folder(self):
        text = self.skill.read_text(encoding="utf-8").replace(
            f"name: {self.skill.parent.name}", "name: something-else", 1)
        self.skill.write_text(text, encoding="utf-8")
        self.assertFlags("must equal folder")

    def test_canonical_skill_name_is_not_reused(self):
        target = self.skill.parent.parent / "sechelix"
        self.skill.parent.rename(target)
        text = (target / "SKILL.md").read_text(encoding="utf-8")
        text = text.replace("name: sechelix-lite", "name: sechelix", 1)
        (target / "SKILL.md").write_text(text, encoding="utf-8")
        self.assertFlags("must not reuse the canonical name")

    def test_manifest_rejects_fields_outside_agent_plugins_v1(self):
        self.edit_manifest(skills=["./skills/sechelix-lite"])
        self.assertFlags("not in Agent Plugins v1.0.0")

    def test_manifest_version_tracks_the_release(self):
        self.edit_manifest(version="0.0.1")
        self.assertFlags("must match the release version")

    def test_keyword_limit(self):
        self.edit_manifest(keywords=[f"k{n}" for n in range(gate.MAX_KEYWORDS + 1)])
        self.assertFlags("keywords; the limit is")

    # -- drift and independence ----------------------------------------------------------

    def test_canonical_status_vocabulary_is_required(self):
        for path in gate.package_files(self.package):
            if path.suffix == ".md":
                path.write_text(
                    path.read_text(encoding="utf-8").replace("DUPLICATE_ROOT_CAUSE", "DUPLICATE"),
                    encoding="utf-8")
        self.assertFlags("DUPLICATE_ROOT_CAUSE")

    def test_vocabulary_matches_whole_terms(self):
        """`BLOCKED_BY_ENVIRONMENT` must not satisfy the requirement for `BLOCKED`."""
        for path in gate.package_files(self.package):
            if path.suffix == ".md":
                text = path.read_text(encoding="utf-8")
                text = text.replace("BLOCKED_BY_ENVIRONMENT", "@@KEEP@@").replace("BLOCKED", "HALTED")
                path.write_text(text.replace("@@KEEP@@", "BLOCKED_BY_ENVIRONMENT"), encoding="utf-8")
        self.assertFlags("'BLOCKED'")

    def test_retired_labels_are_rejected(self):
        self.append(self.skill, "\nMark weak items `SUSPECTED`.\n")
        self.assertFlags("retired label SUSPECTED")

    def test_runtime_dependency_is_rejected(self):
        self.append(self.skill, "\nRun `python scripts/security_gate.py report.json`.\n")
        self.assertFlags("depends on the repository script")

    def test_runtime_package_import_is_rejected(self):
        self.append(self.references / "verification.md", "\nUse sechelix_core.attack_chains.\n")
        self.assertFlags("depends on the SecHelix Python package")

    # -- scope and hygiene ---------------------------------------------------------------

    def test_promotional_copy_is_rejected(self):
        self.append(self.skill, "\nThe most advanced review, backed by a 546 item catalog.\n")
        self.assertFlags("promotional or product copy")

    def test_out_of_scope_workflows_are_rejected(self):
        self.append(self.skill, "\nAlso run an SEO audit.\n")
        self.assertFlags("out-of-scope workflow text")

    def test_secrets_are_rejected(self):
        self.append(self.references / "reporting.md", "\ntoken: ghp_" + "a" * 36 + "\n")
        self.assertTrue(any("ghp_" in p or "token" in p.lower() for p in self.problems()))

    def test_clean_install_catches_paths_outside_the_plugin(self):
        self.append(self.skill, "\nSee [canonical](../../../../skills/sechelix/SKILL.md).\n")
        self.assertFlags("reaches outside the plugin")


if __name__ == "__main__":
    unittest.main()
