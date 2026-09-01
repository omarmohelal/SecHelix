"""Diff content that looks like a diff header must not be eaten as one.

`---` and `+++` are file headers only before the first hunk. Inside a hunk they
are content: removing the SQL comment `-- x` produces the line `--- x`.

Treating that as a header made the removed line disappear, so a diff that removed
`-- ALTER TABLE orders ENABLE ROW LEVEL SECURITY;` classified as `UNCHANGED`. A
silent miss is the worst outcome a classifier can produce — worse than a false
positive, because nothing signals that anything was skipped.
"""

import unittest

from sechelix_core.diff_review import parse_unified_diff, review_diff

SQL_COMMENT_REMOVED = """diff --git a/migrations/003.sql b/migrations/003.sql
--- a/migrations/003.sql
+++ b/migrations/003.sql
@@ -1,2 +1,1 @@
--- ALTER TABLE orders ENABLE ROW LEVEL SECURITY;
 SELECT 1;
"""

SQL_COMMENT_ADDED = """diff --git a/migrations/004.sql b/migrations/004.sql
--- a/migrations/004.sql
+++ b/migrations/004.sql
@@ -1,1 +1,2 @@
 SELECT 1;
+-- CREATE POLICY tenant_isolation ON orders USING (tenant_id = current_tenant());
"""

ORDINARY = """diff --git a/app/x.py b/app/x.py
--- a/app/x.py
+++ b/app/x.py
@@ -1,2 +1,2 @@
-old = 1
+new = 2
"""


class HeaderAmbiguityTests(unittest.TestCase):
    def test_a_removed_sql_comment_is_not_swallowed(self):
        files = parse_unified_diff(SQL_COMMENT_REMOVED)
        self.assertEqual(len(files), 1)
        self.assertEqual(
            files[0].removed,
            ("-- ALTER TABLE orders ENABLE ROW LEVEL SECURITY;",),
        )

    def test_a_removed_rls_statement_is_classified_not_ignored(self):
        result = review_diff(SQL_COMMENT_REMOVED)
        self.assertNotEqual(result["overall"], "UNCHANGED", result)
        self.assertTrue(result["deltas"], "the removed policy produced no delta")

    def test_an_added_sql_comment_is_not_swallowed(self):
        files = parse_unified_diff(SQL_COMMENT_ADDED)
        self.assertEqual(len(files), 1)
        self.assertTrue(
            any("CREATE POLICY" in line for _, line in files[0].added),
            files[0].added,
        )

    def test_the_path_is_still_read_from_the_header(self):
        for text, expected in (
            (SQL_COMMENT_REMOVED, "migrations/003.sql"),
            (SQL_COMMENT_ADDED, "migrations/004.sql"),
            (ORDINARY, "app/x.py"),
        ):
            with self.subTest(expected):
                self.assertEqual(parse_unified_diff(text)[0].path, expected)

    def test_a_second_file_resets_header_parsing(self):
        """After one file's hunk, the next file's headers must parse as headers."""
        combined = SQL_COMMENT_REMOVED + SQL_COMMENT_ADDED
        files = parse_unified_diff(combined)
        self.assertEqual([f.path for f in files],
                         ["migrations/003.sql", "migrations/004.sql"])

    def test_ordinary_diffs_are_unaffected(self):
        files = parse_unified_diff(ORDINARY)
        self.assertEqual(files[0].removed, ("old = 1",))
        self.assertEqual([line for _, line in files[0].added], ["new = 2"])


if __name__ == "__main__":
    unittest.main()
