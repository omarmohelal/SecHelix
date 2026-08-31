from copy import deepcopy
import subprocess
import sys
import unittest

from sechelix_core.catalog import expected_ids
from sechelix_core.contracts import ContractValidationError, ROOT, load_json, validate_contract


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_json(ROOT / "catalog" / "checks.json")

    def test_catalog_has_exact_explicit_stable_cross_product(self) -> None:
        validate_contract("catalog", self.catalog)
        self.assertEqual(21, len(self.catalog["families"]))
        self.assertEqual(26, len(self.catalog["lenses"]))
        self.assertEqual(546, len(self.catalog["hypotheses"]))
        self.assertEqual(
            expected_ids(self.catalog["families"], self.catalog["lenses"]),
            [item["id"] for item in self.catalog["hypotheses"]],
        )
        self.assertEqual({"HYPOTHESIS"}, {item["claim_status"] for item in self.catalog["hypotheses"]})

    def test_catalog_rejects_mutated_identity(self) -> None:
        mutated = deepcopy(self.catalog)
        mutated["hypotheses"][1]["id"] = mutated["hypotheses"][0]["id"]
        with self.assertRaises(ContractValidationError):
            validate_contract("catalog", mutated)

    def test_catalog_rejects_malformed_reference(self) -> None:
        mutated = deepcopy(self.catalog)
        malformed = "https://"
        mutated["families"][0]["references"] = [malformed]
        for hypothesis in mutated["hypotheses"][:26]:
            hypothesis["references"] = [malformed]
        with self.assertRaises(ContractValidationError):
            validate_contract("catalog", mutated)

    def test_generator_is_reproducible(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate_catalog.py"), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
