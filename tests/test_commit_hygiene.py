import unittest

from scripts.check_commit_hygiene import DEPENDENCY_BOT_EMAILS, MAX_BODY_LINES, check_message


DEPENDABOT = "49699333+dependabot[bot]@users.noreply.github.com"
LONG_BODY = "subject\n\n" + "\n".join(f"line {n}" for n in range(MAX_BODY_LINES + 5))


class CommitHygieneTests(unittest.TestCase):
    def test_a_long_human_body_is_rejected(self):
        self.assertTrue(check_message("a" * 40, LONG_BODY, "someone@example.com"))

    def test_generated_dependency_release_notes_are_not_a_diary(self):
        self.assertIn(DEPENDABOT, DEPENDENCY_BOT_EMAILS)
        self.assertEqual(check_message("b" * 40, LONG_BODY, DEPENDABOT), [])

    def test_a_bot_author_does_not_waive_forbidden_trailers(self):
        message = "subject\n\nCo-Authored-By: Claude <noreply@anthropic.com>"
        self.assertTrue(check_message("c" * 40, message, DEPENDABOT))

    def test_a_short_body_passes(self):
        self.assertEqual(check_message("d" * 40, "subject\n\nOne line.", "someone@example.com"), [])


if __name__ == "__main__":
    unittest.main()
