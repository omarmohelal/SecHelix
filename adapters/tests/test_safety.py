from __future__ import annotations

import json
from pathlib import Path
import unittest

from adapters import AdapterError
from adapters.safety import ScanContext, authorize_target, nuclei_safe_command, zap_passive_command


HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"
PROFILES = HERE.parent / "profiles"


class SafeProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.template = str((FIXTURES / "safe-template.yaml").resolve())

    def test_zap_builder_is_baseline_passive_and_local(self) -> None:
        command = zap_passive_command(
            "http://127.0.0.1:3000",
            "zap.json",
            ScanContext(mode="local"),
        )
        self.assertIn("zap-baseline.py", command)
        self.assertNotIn("zap-full-scan.py", command)
        self.assertNotIn("zap-api-scan.py", command)

    def test_local_mode_rejects_non_loopback_targets(self) -> None:
        with self.assertRaises(AdapterError):
            authorize_target("https://example.com", ScanContext(mode="local"))

    def test_staging_requires_exact_host_allowlist(self) -> None:
        context = ScanContext(mode="staging", allowed_hosts=("staging.internal.example",))
        self.assertEqual(
            authorize_target("https://staging.internal.example/health", context),
            "https://staging.internal.example/health",
        )
        with self.assertRaises(AdapterError):
            authorize_target("https://other.internal.example", context)

    def test_production_and_uncontrolled_modes_are_rejected(self) -> None:
        for mode in ("production", "production-safe", "uncontrolled", ""):
            with self.subTest(mode=mode), self.assertRaises(AdapterError):
                authorize_target("http://127.0.0.1:3000", ScanContext(mode=mode))

    def test_nuclei_requires_explicit_local_template_allowlist(self) -> None:
        context = ScanContext(mode="local", allowed_templates=(self.template,))
        command = nuclei_safe_command(
            "http://localhost:3000", [self.template], "nuclei.jsonl", context
        )
        self.assertIn("-disable-update-check", command)
        self.assertEqual(command.count("-t"), 1)
        self.assertIn(self.template, command)

    def test_nuclei_rejects_remote_or_unlisted_templates(self) -> None:
        context = ScanContext(mode="local", allowed_templates=(self.template,))
        for template in ("https://templates.example/check.yaml", str(FIXTURES / "other.yaml")):
            with self.subTest(template=template), self.assertRaises(AdapterError):
                nuclei_safe_command("http://localhost:3000", [template], "out.jsonl", context)

    def test_staging_nuclei_needs_both_allowlists(self) -> None:
        context = ScanContext(
            mode="staging",
            allowed_hosts=("staging.internal.example",),
            allowed_templates=(self.template,),
        )
        command = nuclei_safe_command(
            "https://staging.internal.example", [self.template], "out.jsonl", context
        )
        self.assertIn("https://staging.internal.example", command)

    def test_checked_in_profiles_are_fail_closed(self) -> None:
        zap = json.loads((PROFILES / "zap-passive-local.json").read_text(encoding="utf-8"))
        local = json.loads((PROFILES / "nuclei-safe-local.json").read_text(encoding="utf-8"))
        staging = json.loads((PROFILES / "nuclei-safe-staging.json").read_text(encoding="utf-8"))
        self.assertIs(zap["active_scan"], False)
        self.assertEqual(local["target_policy"], "loopback-only")
        self.assertEqual(staging["target_policy"], "explicit-host-allowlist")
        self.assertIn("remote-templates", local["disabled_capabilities"])


if __name__ == "__main__":
    unittest.main()
