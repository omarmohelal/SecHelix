import tempfile
import unittest
from pathlib import Path

from scripts.check_install_snippets import check as check_install
from scripts.check_local_links import check_file
from scripts.check_no_secrets import scan_text
from scripts.check_private_site_leakage import find_violations
from scripts.sync_portable_skill import DEST as PORTABLE_SKILL


ROOT = Path(__file__).resolve().parents[1]


class RepositoryCheckTests(unittest.TestCase):
    def test_private_site_paths_and_source_maps_are_rejected(self):
        violations = find_violations(["SecHelix-Site-Private/src/app.tsx", "assets/private.js.map"])
        self.assertEqual(len(violations), 2)

    def test_historical_public_site_is_allowed(self):
        self.assertEqual(find_violations(["site/index.html", "site/app.js"]), [])

    def test_secret_scanner_detects_high_confidence_tokens(self):
        sample = "ghp_" + ("a" * 28)
        findings = scan_text(Path("fixture.txt"), sample)
        self.assertTrue(findings)

    def test_secret_scanner_allows_redacted_values(self):
        self.assertEqual(scan_text(Path("fixture.json"), '"api_key": "[REDACTED]"'), [])

    def test_local_link_checker_detects_missing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "doc.md"
            path.write_text("[missing](nope.md)\n", encoding="utf-8")
            self.assertEqual(len(check_file(path)), 1)

    def test_install_snippets_are_current(self):
        self.assertEqual(check_install(ROOT), [])

    def test_portable_skill_is_self_contained(self):
        text = (PORTABLE_SKILL / "SKILL.md").read_text(encoding="utf-8")
        self.assertNotIn("../../", text)
        for path in (
            "catalog/checks.json",
            "agents/independent-verifier.md",
            "schemas/report-v1.schema.json",
            "adapters/cli.py",
            "reports/report_renderer.py",
            "scripts/security_gate.py",
        ):
            self.assertTrue((PORTABLE_SKILL / path).is_file(), path)


if __name__ == "__main__":
    unittest.main()
