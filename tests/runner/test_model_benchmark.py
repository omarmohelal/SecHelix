from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from sechelix_runner.model_benchmark import (
    ModelBenchmarkError,
    load_blind_cases,
    parse_label,
    run_nexus_benchmark,
)
from sechelix_runner.providers.base import ProviderResult


class _FakeNexus:
    def __init__(self, text: str = "CLEAN") -> None:
        self.text = text

    def invoke(self, prompt: str, *, timeout: float):
        self.last_prompt = prompt
        self.last_timeout = timeout
        return ProviderResult(
            text=self.text,
            model="fixture-model",
            provider="fixture-provider",
            input_tokens=10,
            output_tokens=1,
            cost_usd=0.01,
        )


class ModelBenchmarkTests(unittest.TestCase):
    def _packet(self, root: Path) -> Path:
        path = root / "cases.json"
        path.write_text(
            json.dumps(
                {
                    "schema_version": "1.1.0",
                    "cases": [
                        {
                            "case_id": "CASE-ONE",
                            "family": "Authorization",
                            "language": "python",
                            "filename": "a.py",
                            "source": "def read(x): return x",
                            "task": "Review authorization.",
                        },
                        {
                            "case_id": "CASE-TWO",
                            "family": "Injection",
                            "language": "python",
                            "filename": "b.py",
                            "source": "def query(x): return x",
                            "task": "Review injection.",
                        },
                    ],
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )
        return path

    def test_load_packet_never_requires_truth_labels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cases, digest = load_blind_cases(self._packet(Path(tmp)))
        self.assertEqual([case.case_id for case in cases], ["CASE-ONE", "CASE-TWO"])
        self.assertEqual(len(digest), 64)

    def test_label_parser_is_fail_closed(self) -> None:
        self.assertEqual(parse_label("VULNERABLE"), "VULNERABLE")
        self.assertEqual(parse_label("analysis\nCLEAN"), "CLEAN")
        with self.assertRaises(ModelBenchmarkError):
            parse_label("VULNERABLE or maybe CLEAN")
        with self.assertRaises(ModelBenchmarkError):
            parse_label("unknown")

    def test_benchmark_freezes_complete_unscored_predictions(self) -> None:
        calls: list[_FakeNexus] = []

        def factory():
            item = _FakeNexus("CLEAN")
            calls.append(item)
            return item

        with tempfile.TemporaryDirectory() as tmp:
            packet = run_nexus_benchmark(
                cases_path=self._packet(Path(tmp)),
                lane="qwen-local",
                sechelix_commit="a" * 40,
                fixture_suite_version="two synthetic cases",
                timeout_per_case=15,
                executor_factory=factory,
            )

        self.assertEqual(packet["case_count"], 2)
        self.assertEqual(len(packet["predictions"]), 2)
        self.assertTrue(all(row["verification_status"] == "NOT_RUN" for row in packet["predictions"]))
        self.assertNotIn("expected", json.dumps(packet))
        self.assertEqual(packet["input_tokens"], 20)
        self.assertEqual(packet["output_tokens"], 2)
        self.assertEqual(packet["cost"], 0.02)
        self.assertEqual(len(calls), 2)
        self.assertTrue(all("Answer with exactly one label" in item.last_prompt for item in calls))

    def test_duplicate_case_ids_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = self._packet(Path(tmp))
            data = json.loads(path.read_text(encoding="utf-8"))
            data["cases"][1]["case_id"] = "CASE-ONE"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ModelBenchmarkError, "duplicate case_id"):
                load_blind_cases(path)


if __name__ == "__main__":
    unittest.main()
