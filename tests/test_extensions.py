import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_extensions import validate
from sechelix_core.contracts import ContractValidationError, validate_contract


ROOT = Path(__file__).resolve().parents[1]


class ExtensionContractTests(unittest.TestCase):
    def example(self):
        return json.loads((ROOT / "examples" / "extension-manifest.example.json").read_text(encoding="utf-8"))

    def test_example_manifest_is_valid(self):
        validate_contract("extension-manifest", self.example())

    def test_community_manifest_cannot_self_promote(self):
        manifest = self.example()
        manifest["lifecycle"] = "OFFICIAL"
        with self.assertRaises(ContractValidationError):
            validate_contract("extension-manifest", manifest)

    def test_manifest_rejects_parent_path_escape(self):
        manifest = self.example()
        manifest["entrypoints"] = ["../outside.py"]
        with self.assertRaises(ContractValidationError):
            validate_contract("extension-manifest", manifest)

    def test_manifest_rejects_destructive_defaults(self):
        manifest = self.example()
        manifest["safety"]["destructive_actions"] = True
        with self.assertRaises(ContractValidationError):
            validate_contract("extension-manifest", manifest)

    def test_checked_in_registry_is_valid(self):
        self.assertEqual(validate(), [])


if __name__ == "__main__":
    unittest.main()
