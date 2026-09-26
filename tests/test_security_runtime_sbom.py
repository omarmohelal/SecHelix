from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import generate_security_runtime_sbom as runtime_sbom


ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = ROOT / "containers" / "security-runtime"


def _properties(component: dict[str, object]) -> dict[str, str]:
    raw = component.get("properties", [])
    assert isinstance(raw, list)
    return {
        str(item["name"]): str(item["value"])
        for item in raw
        if isinstance(item, dict) and "name" in item and "value" in item
    }


class SecurityRuntimeSbomTests(unittest.TestCase):
    def build(self) -> dict[str, object]:
        with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            return runtime_sbom.build_bom()

    def test_inventory_is_complete_unique_and_explicitly_not_published_provenance(self) -> None:
        bom = self.build()
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["specVersion"], "1.5")
        components = bom["components"]
        self.assertIsInstance(components, list)
        assert isinstance(components, list)
        self.assertGreater(len(components), 20)

        refs = [str(item["bom-ref"]) for item in components]
        self.assertEqual(len(refs), len(set(refs)))

        metadata = bom["metadata"]
        assert isinstance(metadata, dict)
        root = metadata["component"]
        assert isinstance(root, dict)
        root_props = _properties(root)
        self.assertEqual(
            root_props["sechelix:inventoryBasis"],
            "repository-locks-not-registry-observation",
        )
        self.assertEqual(
            root_props["sechelix:publishedImageProvenance"],
            "NOT_MEASURED",
        )
        self.assertRegex(root_props["sechelix:runtimeLockSha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(root_props["sechelix:pythonLockSha256"], r"^[0-9a-f]{64}$")

    def test_base_image_and_direct_tools_match_repository_lock(self) -> None:
        bom = self.build()
        lock = json.loads(
            (RUNTIME_DIR / "runtime-lock.json").read_text(encoding="utf-8")
        )
        components = {
            str(item["bom-ref"]): item
            for item in bom["components"]
        }

        base_digest = lock["base_image"]["index_sha256"]
        base = components[f"oci:base@sha256:{base_digest}"]
        self.assertEqual(
            _properties(base)["sechelix:ociReference"],
            lock["base_image"]["reference"],
        )

        semgrep_version = lock["python_tools"]["semgrep"]["version"]
        pip_audit_version = lock["python_tools"]["dependency-audit"]["version"]
        for name, version in (
            ("semgrep", semgrep_version),
            ("pip-audit", pip_audit_version),
        ):
            component = components[f"pkg:pypi/{name}@{version}"]
            props = _properties(component)
            self.assertEqual(props["sechelix:pinning"], "sha256-python-lock")
            hashes = props["sechelix:artifactSha256Set"].split(",")
            self.assertTrue(hashes)
            self.assertTrue(all(len(value) == 64 for value in hashes))

    def test_binary_tool_archives_preserve_per_arch_hash_provenance(self) -> None:
        bom = self.build()
        lock = json.loads(
            (RUNTIME_DIR / "runtime-lock.json").read_text(encoding="utf-8")
        )
        components = {
            str(item["bom-ref"]): item
            for item in bom["components"]
        }
        for name in ("gitleaks", "trivy"):
            version = lock["binary_tools"][name]["version"]
            component = components[f"tool:{name}@{version}"]
            props = _properties(component)
            self.assertEqual(props["sechelix:pinning"], "sha256-release-asset")
            for arch in ("amd64", "arm64"):
                self.assertEqual(
                    props[f"sechelix:asset:{arch}:sha256"],
                    lock["binary_tools"][name]["assets"][arch]["sha256"],
                )

    def test_dependencies_point_only_at_declared_components(self) -> None:
        bom = self.build()
        components = bom["components"]
        dependencies = bom["dependencies"]
        assert isinstance(components, list)
        assert isinstance(dependencies, list)
        refs = {str(item["bom-ref"]) for item in components}
        root_ref = str(bom["metadata"]["component"]["bom-ref"])
        declared = refs | {root_ref}
        for edge in dependencies:
            self.assertIn(str(edge["ref"]), declared)
            for child in edge["dependsOn"]:
                self.assertIn(str(child), declared)

    def test_source_date_epoch_makes_output_metadata_reproducible(self) -> None:
        with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}):
            first = runtime_sbom.build_bom()
            second = runtime_sbom.build_bom()
        self.assertEqual(first, second)
        self.assertEqual(
            first["metadata"]["timestamp"],
            "2023-11-14T22:13:20Z",
        )

    def test_unhashed_python_package_fails_closed(self) -> None:
        runtime_lock = RUNTIME_DIR / "runtime-lock.json"
        with tempfile.TemporaryDirectory() as tmp:
            python_lock = Path(tmp) / "python-tools.lock"
            python_lock.write_text("demo==1.0.0\n", encoding="utf-8")
            with self.assertRaises(runtime_sbom.RuntimeSbomError):
                runtime_sbom.build_bom(runtime_lock, python_lock)


if __name__ == "__main__":
    unittest.main()
