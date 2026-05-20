"""Regression: a crafted From-header local-part must not escape working_path.

process_inbox_email derives the per-submission processing directory from the
From-header local-part. Before the fix it used the raw value directly, so a
From like <"../../x"@a.b> traversed out of working_path on mkdir(parents=True).
The local-part (and the source_ref prefix) now go through _sanitize_filename.

These tests exercise the real _sanitize_filename and reproduce the exact path
composition from process_inbox_email, asserting the result always stays under
the working_path root.
"""
import pathlib
import unittest

from classes.services.mailbox_service import Mailbox


def _compose_processing_dir(sanitizer, tmp_path: pathlib.Path, email_from: str, source_ref: str) -> pathlib.Path:
    """Mirror the path composition in MailboxService.process_inbox_email."""
    safe_local = sanitizer(email_from.split("@")[0], 0, default_base="submitter")
    folder_name = f"{safe_local}-submission"
    safe_ref = sanitizer(source_ref.split("-", maxsplit=1)[0], 0, default_base="ref")
    return pathlib.Path(tmp_path, f"{folder_name}-{safe_ref}")


class PathTraversalTests(unittest.TestCase):
    def setUp(self):
        # Build an instance without running __init__ (which needs an IMAP client).
        self.svc = Mailbox.__new__(Mailbox)
        self.sanitizer = self.svc._sanitize_filename
        self.tmp = pathlib.Path("/tmp/feeder-work").resolve()

    def _assert_contained(self, email_from: str, source_ref: str = "ref-123"):
        composed = _compose_processing_dir(self.sanitizer, self.tmp, email_from, source_ref)
        resolved = composed.resolve()
        self.assertTrue(
            str(resolved).startswith(str(self.tmp)),
            msg=f"{email_from!r} escaped working_path: {resolved}",
        )
        # No path separators survived into the directory name component.
        name = composed.name
        self.assertNotIn("/", name)
        self.assertNotIn("\\", name)

    def test_dotdot_local_part_stays_contained(self):
        self._assert_contained('"../../etc/passwd"')

    def test_slash_local_part_stays_contained(self):
        self._assert_contained("a/b/c")

    def test_backslash_local_part_stays_contained(self):
        self._assert_contained("a\\b\\c")

    def test_bare_dotdot_is_not_a_parent_segment(self):
        composed = _compose_processing_dir(self.sanitizer, self.tmp, "..", "ref-1")
        self.assertNotEqual(composed.name, "..")
        self.assertTrue(str(composed.resolve()).startswith(str(self.tmp)))

    def test_empty_local_part_falls_back_to_default(self):
        composed = _compose_processing_dir(self.sanitizer, self.tmp, "@no-local", "ref-1")
        self.assertIn("submitter", composed.name)
        self.assertTrue(str(composed.resolve()).startswith(str(self.tmp)))

    def test_normal_local_part_is_preserved(self):
        composed = _compose_processing_dir(self.sanitizer, self.tmp, "jane.doe@corp.com", "ref-9")
        self.assertIn("jane.doe", composed.name)

    def test_sanitizer_strips_path_separators(self):
        out = self.sanitizer("../../x", 0)
        self.assertNotIn("/", out)
        self.assertNotIn("\\", out)


if __name__ == "__main__":
    unittest.main()
