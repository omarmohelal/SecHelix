"""A file that describes a risk is not a file that has one.

Running the differential reviewer over this project's own V3.4 release produced
deltas for a policy rule named `MCP-WRITE-AUTHORIZATION` (matched by the AI-tool
detector), a JSON Schema's own redaction pattern containing the word "signature"
(matched by the webhook detector), and every `"schema_version": "1.0"` in the
repository (matched by the dependency detector).

None of those lines execute. A schema states a shape and a policy pack states
what to look for, so running the detectors over them flags the description of a
risk as the risk itself.
"""

import unittest

from sechelix_core.diff_review import review_diff


def diff_for(path, added_lines):
    header = (
        f"diff --git a/{path} b/{path}\n"
        f"--- a/{path}\n"
        f"+++ b/{path}\n"
        f"@@ -1,1 +1,{len(added_lines)} @@\n"
    )
    return header + "".join("+" + line + "\n" for line in added_lines)


def kinds_for(path, added_lines):
    return {d["kind"] for d in review_diff(diff_for(path, added_lines))["deltas"]}


class DeclarationTests(unittest.TestCase):
    def test_a_schema_describing_a_risk_is_not_a_delta(self):
        kinds = kinds_for("schemas/mcp-graph-v1.schema.json", [
            '  "$id": "https://sechelix.com/schemas/mcp-graph-v1.schema.json",',
            '  "description": "signature and hmac verification of the webhook",',
            '  "schema_version": "1.0",',
        ])
        self.assertEqual(kinds - {"secret"}, set(), kinds)

    def test_a_policy_pack_naming_what_to_look_for_is_not_a_delta(self):
        kinds = kinds_for("policies/packs/production-default.json", [
            '  "rule_id": "MCP-WRITE-AUTHORIZATION",',
            '  "surface_patterns": ["payment", "billing", "checkout", "refund"],',
            '  "statement": "An MCP tool with write capability requires review.",',
        ])
        self.assertEqual(kinds - {"secret"}, set(), kinds)

    def test_a_documented_version_number_is_not_a_dependency_change(self):
        """The dependency that matters lives in a lockfile, not in prose."""
        kinds = kinds_for("docs/reference/policy-packs.md", ['  "version": "1.0.0",'])
        self.assertNotIn("dependency", kinds)

    def test_a_credential_in_a_declaration_file_is_still_reported(self):
        token = "sk" + "-live-abcdefghijklmnop"
        kinds = kinds_for("schemas/x-v1.schema.json", [f'  "default": "api_key={token}",'])
        self.assertIn("secret", kinds)

    def test_a_credential_in_prose_is_still_reported(self):
        token = "gh" + "p_abcdefghijklmnopqrstuvwxyz0123456789"
        kinds = kinds_for("docs/x.md", [f"The token is api_key={token} in the example."])
        self.assertIn("secret", kinds)


class StillDetectedTests(unittest.TestCase):
    """Suppressing declarations must not suppress the code they describe."""

    def test_real_code_in_an_ordinary_json_file_is_still_read(self):
        kinds = kinds_for("package.json", ['    "express": "^4.18.0",'])
        self.assertIn("dependency", kinds)

    def test_real_application_code_is_unaffected(self):
        kinds = kinds_for("app/api.py", [
            "sig = request.headers['stripe-signature']",
            "url = s3.getSignedUrl(bucket, key)",
        ])
        self.assertIn("webhook", kinds)
        self.assertIn("storage_access", kinds)

    def test_a_config_file_outside_policies_is_still_read(self):
        kinds = kinds_for("config/settings.json", ['  "express": "^4.18.0",'])
        self.assertIn("dependency", kinds)

    def test_a_windows_style_declaration_path_is_recognised(self):
        kinds = kinds_for("policies\\\\packs\\\\prod.json", ['  "rule_id": "MCP-WRITE",'])
        self.assertEqual(kinds - {"secret"}, set(), kinds)


if __name__ == "__main__":
    unittest.main()
