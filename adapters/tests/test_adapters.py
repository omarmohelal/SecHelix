from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from adapters import ADAPTERS, AdapterError, parse
from adapters.cli import main


FIXTURES = Path(__file__).parent / "fixtures"


class AdapterContractTests(unittest.TestCase):
    CASES = (
        ("semgrep", "semgrep.json", "semgrep"),
        ("opengrep", "semgrep.json", "opengrep"),
        ("sarif", "sarif.json", "Example SARIF Scanner"),
        ("codeql", "codeql.sarif", "codeql"),
        ("osv", "osv.json", "osv"),
        ("trivy", "trivy.json", "trivy"),
        ("gitleaks", "gitleaks.json", "gitleaks"),
        ("npm-audit", "npm-audit.json", "npm-audit"),
        ("pnpm-audit", "pnpm-audit.json", "pnpm-audit"),
        ("playwright", "playwright.json", "playwright"),
        ("zap", "zap.json", "zap"),
        ("nuclei", "nuclei.jsonl", "nuclei"),
    )

    def _records(self, adapter: str, fixture: str) -> list[dict[str, object]]:
        return parse(adapter, (FIXTURES / fixture).read_bytes())

    def test_registry_contains_every_supported_adapter(self) -> None:
        self.assertEqual(
            set(ADAPTERS),
            {"semgrep", "opengrep", "sarif", "codeql", "osv", "trivy", "gitleaks", "npm-audit", "pnpm-audit", "playwright", "zap", "nuclei"},
        )

    def test_every_fixture_emits_candidate_unassessed_records(self) -> None:
        for adapter, fixture, expected_tool in self.CASES:
            with self.subTest(adapter=adapter):
                records = self._records(adapter, fixture)
                self.assertGreater(len(records), 0)
                for record in records:
                    self.assertEqual(record["schema_version"], "sechelix-evidence/v1")
                    self.assertEqual(record["status"], "CANDIDATE")
                    self.assertEqual(record["assessment"], "UNASSESSED")
                    self.assertEqual(record["severity"], "UNASSESSED")
                    self.assertEqual(record["verification"], "UNASSESSED")
                    self.assertEqual(record["source"]["tool"], expected_tool)
                    signal = record["tool_signal"]
                    if signal:
                        self.assertIs(signal["trusted_for_assessment"], False)

    def test_opengrep_keeps_engine_provenance_distinct(self) -> None:
        record = self._records("opengrep", "semgrep.json")[0]
        self.assertEqual(record["source"]["tool"], "opengrep")
        self.assertEqual(record["properties"]["engine"], "opengrep")
        self.assertEqual(record["status"], "CANDIDATE")
        self.assertEqual(record["assessment"], "UNASSESSED")

    def test_high_and_critical_tool_labels_never_promote_assessment(self) -> None:
        for adapter, fixture in (
            ("osv", "osv.json"),
            ("trivy", "trivy.json"),
            ("npm-audit", "npm-audit.json"),
            ("pnpm-audit", "pnpm-audit.json"),
            ("zap", "zap.json"),
            ("nuclei", "nuclei.jsonl"),
        ):
            with self.subTest(adapter=adapter):
                for record in self._records(adapter, fixture):
                    self.assertEqual(
                        (record["status"], record["severity"], record["assessment"]),
                        ("CANDIDATE", "UNASSESSED", "UNASSESSED"),
                    )

    def test_secret_material_is_not_emitted(self) -> None:
        cases = (
            ("trivy", "trivy.json", "TRIVY_FIXTURE_SECRET_123"),
            ("gitleaks", "gitleaks.json", "GITLEAKS_FIXTURE_SECRET_456"),
            ("nuclei", "nuclei.jsonl", "NUCLEI_FIXTURE_SECRET_789"),
        )
        for adapter, fixture, secret in cases:
            with self.subTest(adapter=adapter):
                rendered = json.dumps(self._records(adapter, fixture), sort_keys=True)
                self.assertNotIn(secret, rendered)
                self.assertIn('"redacted": true', rendered)

    def test_ids_are_deterministic(self) -> None:
        first = self._records("semgrep", "semgrep.json")
        second = self._records("semgrep", "semgrep.json")
        self.assertEqual(first[0]["evidence_id"], second[0]["evidence_id"])

    def test_malformed_json_fails_closed(self) -> None:
        with self.assertRaises(AdapterError):
            parse("semgrep", b"{not json")
        with self.assertRaises(AdapterError):
            parse("opengrep", b"{not json")
        with self.assertRaises(AdapterError):
            parse("sarif", b"[]")

    def test_cli_emits_trust_boundary(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            result = main(["semgrep", str(FIXTURES / "semgrep.json")])
        self.assertEqual(result, 0)
        document = json.loads(stdout.getvalue())
        self.assertIn("CANDIDATE/UNASSESSED", document["trust_boundary"])
        self.assertEqual(document["records"][0]["severity"], "UNASSESSED")

    def test_cli_can_write_explicit_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "normalized.json"
            result = main(["codeql", str(FIXTURES / "codeql.sarif"), "-o", str(output)])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["adapter"], "codeql")


if __name__ == "__main__":
    unittest.main()
