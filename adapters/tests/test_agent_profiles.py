from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).parents[2]
AGENTS = ROOT / "agents"


class AgentProfileContractTests(unittest.TestCase):
    EXPECTED = {
        "mapper.md",
        "auth.md",
        "authz.md",
        "injection-web.md",
        "ssrf-file-parser.md",
        "business-logic.md",
        "payments-accounting.md",
        "race-idempotency.md",
        "database-rls-migrations.md",
        "browser-extension.md",
        "supply-chain.md",
        "ci-cd-cloud.md",
        "ai-mcp-agent-security.md",
        "privacy-logging.md",
        "independent-verifier.md",
        "remediation-reviewer.md",
        "regression-release-verifier.md",
    }
    HEADINGS = (
        "## Mission",
        "## Boundaries",
        "## Inputs",
        "## Evidence standard",
        "## What not to do",
        "## Output schema",
    )

    def test_all_specialist_profiles_exist_and_are_complete(self) -> None:
        actual = {path.name for path in AGENTS.glob("*.md")} - {"README.md"}
        self.assertEqual(actual, self.EXPECTED)
        for filename in sorted(self.EXPECTED):
            content = (AGENTS / filename).read_text(encoding="utf-8")
            with self.subTest(profile=filename):
                for heading in self.HEADINGS:
                    self.assertIn(heading, content)

    def test_hunters_do_not_claim_verified_or_assigned_severity(self) -> None:
        non_hunters = {
            "independent-verifier.md",
            "remediation-reviewer.md",
            "regression-release-verifier.md",
        }
        for filename in self.EXPECTED - non_hunters:
            content = (AGENTS / filename).read_text(encoding="utf-8")
            with self.subTest(profile=filename):
                self.assertIn('"status": "CANDIDATE"', content)
                self.assertIn('"severity": "UNASSESSED"', content)

    def test_model_mesh_keeps_benchmarks_unmeasured(self) -> None:
        content = (ROOT / "docs" / "model-mesh.md").read_text(encoding="utf-8")
        self.assertIn("NOT_MEASURED", content)
        self.assertIn("model name", content)
        self.assertIn("independent", content)


if __name__ == "__main__":
    unittest.main()
