"""The runner must stay optional.

These are structural guards, not style checks. The portable Agent Skill is the
product; the runner is an accelerant. The moment ``sechelix_core`` imports
anything from ``sechelix_runner``, the skill has silently acquired a dependency
and a cold install starts failing for everyone who never asked for a runtime.
"""

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            # A relative import (level > 0) is always in-package. Its `module`
            # is the bare name, so without this it looks like a third-party dep.
            if node.level:
                names.add("." + (node.module or ""))
            elif node.module:
                names.add(node.module)
    return names


class RunnerStaysOptionalTests(unittest.TestCase):
    def test_core_never_imports_the_runner(self) -> None:
        for path in sorted((ROOT / "sechelix_core").glob("*.py")):
            with self.subTest(module=path.name):
                offenders = {n for n in _imported_modules(path) if "sechelix_runner" in n}
                self.assertEqual(offenders, set(), f"{path.name} imports the runner")

    def test_adapters_never_import_the_runner(self) -> None:
        for path in sorted((ROOT / "adapters").rglob("*.py")):
            with self.subTest(module=path.name):
                offenders = {n for n in _imported_modules(path) if "sechelix_runner" in n}
                self.assertEqual(offenders, set(), f"{path.name} imports the runner")

    def test_portable_skill_ships_no_runner_copy(self) -> None:
        """The skill is synced from the repo; the runner must not ride along."""
        self.assertFalse((ROOT / "skills" / "sechelix" / "sechelix_runner").exists())

    def test_runner_depends_only_on_the_standard_library(self) -> None:
        allowed_prefixes = (
            # runner -> core is the allowed direction; core -> runner is what
            # the other tests in this class forbid.
            "sechelix_runner", "sechelix_core", ".", "__future__", "dataclasses",
            "typing", "enum",
            "json", "hashlib", "uuid", "time", "datetime", "pathlib", "collections",
            "argparse", "os", "sys", "re", "itertools", "contextlib", "shutil",
            "subprocess", "tempfile", "textwrap", "math", "copy", "abc", "functools",
            "ipaddress", "socket", "urllib", "base64", "secrets", "string",
            "http", "threading", "http.server", "html",
        )
        for path in sorted((ROOT / "sechelix_runner").glob("*.py")):
            with self.subTest(module=path.name):
                for name in _imported_modules(path):
                    root = name.split(".")[0] or "."
                    self.assertTrue(
                        name.startswith(".") or root in allowed_prefixes,
                        f"{path.name} imports third-party module {name!r}",
                    )


if __name__ == "__main__":
    unittest.main()
