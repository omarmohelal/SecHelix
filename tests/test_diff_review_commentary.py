"""Prose inside a code file describes behaviour; it does not change it.

Running the differential reviewer over this project's own V3.3 diff produced
deltas for a docstring saying a digest "is not a signature" and a JSON Schema
`description` mentioning a sample-size bucket. Neither line does anything, and
reporting them is the false-positive class this project exists to reject.

These tests fix the boundary in both directions: prose is suppressed, behaviour
on the same surface is not, and a credential in a comment is still a credential.
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


def deltas_for(path, added_lines):
    return review_diff(diff_for(path, added_lines))["deltas"]


class SuppressedTests(unittest.TestCase):
    def test_a_comment_mentioning_a_surface_is_not_a_delta(self):
        found = deltas_for("app/x.py", [
            "# the webhook signature is checked upstream",
            "# we read from the s3 bucket here",
            "// an outbound fetch happens elsewhere",
        ])
        self.assertEqual(found, [], found)

    def test_a_docstring_body_is_not_a_delta(self):
        found = deltas_for("app/x.py", [
            "def f():",
            '    """Explain the design.',
            "",
            "    The digest is not a signature, and the bucket is a sample bucket.",
            '    """',
            "    return 1",
        ])
        noisy = [d for d in found if d["kind"] in {"webhook", "storage_access"}]
        self.assertEqual(noisy, [], noisy)

    def test_a_json_description_is_not_a_delta(self):
        found = deltas_for("schemas/x.schema.json", [
            '  "description": "Below this a bucket rate is noise; no signature is present",',
            '  "title": "webhook and bucket wording",',
        ])
        noisy = [d for d in found if d["kind"] in {"webhook", "storage_access"}]
        self.assertEqual(noisy, [], noisy)

    def test_a_blank_line_is_never_a_delta(self):
        self.assertEqual(deltas_for("app/x.py", ["", "   ", "\t"]), [])


class NotSuppressedTests(unittest.TestCase):
    """Suppressing prose must not suppress behaviour on the same surface."""

    def test_real_storage_code_is_still_a_delta(self):
        found = deltas_for("app/x.py", ["url = s3.getSignedUrl(bucket, key)"])
        self.assertTrue(any(d["kind"] == "storage_access" for d in found), found)

    def test_real_webhook_code_is_still_a_delta(self):
        found = deltas_for("app/x.py", ["sig = request.headers['stripe-signature']"])
        self.assertTrue(any(d["kind"] == "webhook" for d in found), found)

    def test_a_secret_in_a_comment_is_still_reported(self):
        """A credential pasted into a comment is still a credential."""
        token = "sk" + "-live-abcdefghijklmnop"
        found = deltas_for("app/x.py", [f"# api_key = {token}"])
        self.assertTrue(any(d["kind"] == "secret" for d in found), found)

    def test_code_after_a_closed_docstring_is_still_read(self):
        """The parity tracker must not swallow the rest of the file."""
        found = deltas_for("app/x.py", [
            '    """A bucket of samples."""',
            "    url = s3.getSignedUrl(bucket, key)",
        ])
        self.assertTrue(any(d["kind"] == "storage_access" for d in found), found)


if __name__ == "__main__":
    unittest.main()
