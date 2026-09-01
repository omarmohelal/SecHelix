"""Every API the skill tells an agent to call must actually exist.

SKILL.md is instructions to an agent, not prose. A function named there that does
not exist is a runtime failure in the middle of someone's security review, and it
is invisible to every other gate in this repository — the catalog validator, the
contract validators and the unit tests all pass while the skill points at nothing.

This happened: SKILL.md documented `diff_review.classify_changes`, which was never
a real function. The module exports `review_diff`.
"""

import importlib
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills" / "sechelix" / "SKILL.md"

#: Matches `sechelix_core.module.callable(` in prose or code, backticked or not.
REFERENCE = re.compile(r"sechelix_core[./](\w+)(?:\.(\w+))?")

#: Referenced as a file path rather than an importable symbol.
PATH_ONLY = re.compile(r"sechelix_core/\w+\.py")


class SkillReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = SKILL.read_text(encoding="utf-8")

    def test_the_skill_exists_and_is_the_canonical_entry_point(self):
        self.assertTrue(SKILL.is_file())
        self.assertFalse((ROOT / "SKILL.md").exists(),
                         "a root SKILL.md makes the CLI package the whole repository")

    def test_every_referenced_module_imports(self):
        modules = {m for m, _ in REFERENCE.findall(self.text)}
        self.assertTrue(modules, "expected SKILL.md to reference sechelix_core modules")
        for module in sorted(modules):
            with self.subTest(module=module):
                importlib.import_module(f"sechelix_core.{module}")

    def test_every_referenced_callable_exists(self):
        # Strip file-path mentions so "sechelix_core/patch_mode.py" is not read
        # as a module attribute named "py".
        text = PATH_ONLY.sub("", self.text)
        checked = 0
        for module_name, attribute in REFERENCE.findall(text):
            if not attribute:
                continue
            with self.subTest(reference=f"{module_name}.{attribute}"):
                module = importlib.import_module(f"sechelix_core.{module_name}")
                self.assertTrue(
                    hasattr(module, attribute),
                    f"SKILL.md tells an agent to call sechelix_core.{module_name}."
                    f"{attribute}, which does not exist",
                )
                checked += 1
        self.assertGreater(checked, 0, "expected at least one callable reference to check")

    def test_the_skill_stays_within_its_context_budget(self):
        """SKILL.md is always-on context; the budget is a real cost, not style."""
        self.assertLess(len(self.text.splitlines()), 500)


if __name__ == "__main__":
    unittest.main()
