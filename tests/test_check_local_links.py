"""The link checker must ignore quoted Markdown without going blind to real breaks."""

import tempfile
import unittest
from pathlib import Path

from scripts.check_local_links import check_file, mask_code


class MaskingTests(unittest.TestCase):
    def test_a_fenced_block_is_masked(self):
        masked = mask_code("before\n```\n[x](../nope.md)\n```\nafter")
        self.assertNotIn("nope.md", masked)

    def test_an_inline_code_span_is_masked(self):
        self.assertNotIn("nope.md", mask_code("see `[x](../nope.md)` above"))

    def test_masking_preserves_line_numbers(self):
        text = "one\n`[x](../nope.md)`\nthree\n"
        masked = mask_code(text)
        self.assertEqual(masked.count("\n"), text.count("\n"))
        self.assertEqual(len(masked), len(text))

    def test_a_real_link_outside_code_survives_masking(self):
        self.assertIn("real.md", mask_code("`code` and [x](real.md)"))

    def test_a_tilde_fence_is_masked(self):
        self.assertNotIn("nope.md", mask_code("~~~\n[x](../nope.md)\n~~~\n"))


class CheckFileTests(unittest.TestCase):
    def _check(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "exists.md").write_text("ok", encoding="utf-8")
            doc = root / "doc.md"
            doc.write_text(body, encoding="utf-8")
            return check_file(doc)

    def test_a_genuinely_broken_link_is_still_reported(self):
        """The masking must not become a way to pass by hiding real breaks."""
        findings = self._check("[gone](missing.md)\n")
        self.assertEqual(len(findings), 1)
        self.assertIn("missing.md", findings[0])

    def test_a_resolving_link_passes(self):
        self.assertEqual(self._check("[here](exists.md)\n"), [])

    def test_quoted_markdown_in_a_code_span_is_not_a_finding(self):
        self.assertEqual(self._check("Their row reads `[Home](../README.md)` verbatim.\n"), [])

    def test_a_broken_link_after_a_code_span_is_reported_on_its_own_line(self):
        findings = self._check("`[q](../q.md)`\n\n[gone](missing.md)\n")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].endswith("3: missing missing.md"), findings[0])


if __name__ == "__main__":
    unittest.main()
