import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from sechelix_core.mistake_memory import MistakeMemory, MistakeObservation

ROOT = Path(__file__).resolve().parents[1]


def load_importer():
    spec = importlib.util.spec_from_file_location("sechelix_import_corpus", ROOT / "evals" / "import_corpus.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class CorpusManifestTests(unittest.TestCase):
    def test_manifest_is_pinned_and_non_vendored(self):
        data = json.loads((ROOT / "evals" / "corpora" / "manifest.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(data["corpora"]), 2)
        for entry in data["corpora"]:
            self.assertFalse(entry["vendored"])
            self.assertIn(entry["identity"]["algorithm"], {"sha256", "git-commit"})
            self.assertTrue(entry["identity"]["value"])
            self.assertTrue(entry["license"]["expression"])
            self.assertTrue(entry["origin"].startswith("https://"))

    def test_importer_has_no_network_client(self):
        source = (ROOT / "evals" / "import_corpus.py").read_text(encoding="utf-8")
        for forbidden in ("urllib", "requests", "http.client", "socket"):
            self.assertNotIn(f"import {forbidden}", source)

    def test_sha256_identity_is_verified_offline(self):
        importer = load_importer()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fixture.bin"
            source.write_bytes(b"fixture")
            import hashlib
            digest = hashlib.sha256(b"fixture").hexdigest()
            entry = {"identity": {"algorithm": "sha256", "value": digest}}
            result = importer.verify_identity(entry, source)
            self.assertEqual(result["verified"], "true")


class MistakeMemoryTests(unittest.TestCase):
    def test_memory_asks_questions_and_never_auto_dismisses(self):
        memory = MistakeMemory()
        memory.add(MistakeObservation(
            mistake_class="trusted-client-gate",
            outcome="FALSE_POSITIVE",
            lesson="A client gate is not the server policy and a shared server control may refute the candidate.",
            verification_question="Which server-side policy decides this subject-object action?",
            domains=("auth", "framework"),
        ))
        exported = memory.export()
        self.assertFalse(exported["observations"][0]["auto_dismiss"])
        self.assertEqual(memory.questions_for(["auth"]), ["Which server-side policy decides this subject-object action?"])

    def test_secret_shaped_memory_is_refused(self):
        with self.assertRaises(ValueError):
            MistakeObservation(
                mistake_class="leak",
                outcome="MISSED",
                lesson="password=example must never be stored",
                verification_question="Was a secret stored?",
            )


class ExamLevelTests(unittest.TestCase):
    def test_eight_levels_are_cumulative(self):
        data = json.loads((ROOT / "knowledge" / "exams" / "levels.json").read_text(encoding="utf-8"))
        levels = data["levels"]
        self.assertEqual([item["level"] for item in levels], list(range(1, 9)))
        ids = [item["id"] for item in levels]
        for index, item in enumerate(levels[1:], start=1):
            self.assertIn(ids[index - 1], item["requires"])


if __name__ == "__main__":
    unittest.main()
