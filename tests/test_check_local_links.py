"""The link checker must ignore quoted Markdown without going blind to real breaks."""

import tempfile
import unittest
from pathlib import Path

from scripts.check_local_links import check_file, mask_code, unclosed_fence


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


class UnclosedFenceTests(unittest.TestCase):
    """An open fence hides links from the renderer AND from this checker."""

    def test_a_balanced_document_reports_nothing(self):
        self.assertIsNone(unclosed_fence("a\n```\ncode\n```\nb\n"))

    def test_an_info_string_opens_but_does_not_close(self):
        self.assertIsNone(unclosed_fence("```python\nx = 1\n```\n"))

    def test_a_nested_fence_needs_a_wider_outer_fence(self):
        """The real defect this found: a ```markdown block wrapping a ```json one."""
        nested = "````markdown\n\n```json\n{}\n```\n\ntext\n````\n"
        self.assertIsNone(unclosed_fence(nested))

    def test_an_equal_width_nested_fence_closes_early(self):
        """Why the outer fence must be wider: the inner closer ends the outer block."""
        self.assertIsNotNone(unclosed_fence("```markdown\n\n```json\n{}\n```\n\ntext\n```\n"))

    def test_an_unclosed_fence_is_reported_with_its_line(self):
        self.assertEqual(unclosed_fence("a\n```\ncode\n```\nb\n```\ndangling\n"), 6)

    def test_a_tilde_fence_closes_a_tilde_fence(self):
        self.assertIsNone(unclosed_fence("~~~\nx\n~~~\n"))

    def test_a_longer_closing_fence_still_closes(self):
        self.assertIsNone(unclosed_fence("```\nx\n````\n"))

    def test_a_document_with_no_fences_is_fine(self):
        self.assertIsNone(unclosed_fence("just prose with `code` in it\n"))

    def test_check_file_surfaces_the_dangling_fence(self):
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "doc.md"
            doc.write_text("intro\n\n```\nnever closed\n", encoding="utf-8")
            findings = check_file(doc)
            self.assertTrue(any("never closed" in f for f in findings), findings)



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
