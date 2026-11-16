"""Walking the tree: what is read, what is skipped, and why."""

import os
import tempfile
import unittest

from pqscan.cli import main
from pqscan.scanner import is_test_path, scan_path


def write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


class Walk(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name

    def tearDown(self):
        self._tmp.cleanup()

    def paths(self, **kwargs):
        return sorted({f.path for f in scan_path(self.root, **kwargs).findings})

    def test_files_without_a_known_extension_are_scanned(self):
        for name in (".env", "Dockerfile", "Makefile", "template.html", "App.JAVA"):
            write(self.root, name, "ALG=RSA-2048\n")
        self.assertEqual(self.paths(),
                         [".env", "App.JAVA", "Dockerfile", "Makefile", "template.html"])

    def test_vendored_and_binary_files_are_skipped(self):
        write(self.root, "node_modules/x/index.js", "RSA-2048\n")
        write(self.root, ".git/config", "RSA-2048\n")
        write(self.root, "package-lock.json", '{"integrity": "sha1-abc"}\n')
        with open(os.path.join(self.root, "blob.dat"), "wb") as fh:
            fh.write(b"\0\1\2RSA-2048\0")
        self.assertEqual(self.paths(), [])

    def test_oversized_files_are_reported_not_silently_dropped(self):
        write(self.root, "big.py", "x = 'RSA-2048'\n" * 2000)
        result = scan_path(self.root, max_file_bytes=1000)
        self.assertEqual(result.oversized, ["big.py"])
        self.assertEqual(result.files_scanned, 0)

    def test_pqscanignore_and_exclude(self):
        write(self.root, "src/a.py", "hashlib.md5(x)\n")
        write(self.root, "legacy/b.py", "hashlib.md5(x)\n")
        write(self.root, "gen/c.py", "hashlib.md5(x)\n")
        write(self.root, ".pqscanignore", "# comment\nlegacy/\n")
        self.assertEqual(self.paths(excludes=["gen/*"]), ["src/a.py"])

    def test_ignore_file_marker(self):
        write(self.root, "a.py", "# pqscan: ignore-file\nhashlib.md5(x)\n")
        self.assertEqual(self.paths(), [])

    def test_skip_tests(self):
        write(self.root, "src/a.py", "hashlib.md5(x)\n")
        write(self.root, "tests/test_a.py", "hashlib.md5(x)\n")
        write(self.root, "src/a_test.go", "md5.Sum(x)\n")
        self.assertEqual(len(self.paths()), 3)
        self.assertEqual(self.paths(skip_tests=True), ["src/a.py"])
        self.assertTrue(is_test_path("pkg/FooTest.java"))
        self.assertTrue(is_test_path("web/app.spec.ts"))
        self.assertFalse(is_test_path("src/contest.py"))

    def test_symlinks_out_of_the_tree_are_not_followed(self):
        outside = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
        outside.write("hashlib.md5(x)\n")
        outside.close()
        try:
            os.symlink(outside.name, os.path.join(self.root, "link.py"))
            os.symlink(self.root, os.path.join(self.root, "loop"))
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        finally:
            self.addCleanup(os.unlink, outside.name)
        self.assertEqual(self.paths(), [])

    def test_non_utf8_text_is_still_read(self):
        with open(os.path.join(self.root, "latin1.py"), "wb") as fh:
            fh.write(b"# caf\xe9\nh = hashlib.md5(x)\n")
        self.assertEqual(self.paths(), ["latin1.py"])

    def test_reports_written_into_the_tree_do_not_feed_the_next_scan(self):
        """v0.2 went 17 -> 130 -> 768 findings over three runs."""
        write(self.root, "app.py", "k = rsa.generate_private_key(65537, 2048)\nh = hashlib.sha1(x)\n")
        outputs = {
            "-o": "report.md", "--html": "report.html", "--cbom": "cbom.json",
            "--sarif": "out.sarif", "--json": "findings.json", "--badge": "badge.svg",
            "--write-baseline": "baseline.json",
        }
        argv = [self.root, "-q"]
        for flag, name in outputs.items():
            argv += [flag, os.path.join(self.root, name)]
        counts = []
        for _ in range(3):
            self.assertEqual(main(argv), 0)
            counts.append(len(scan_path(self.root).findings))
        self.assertEqual(counts, [counts[0]] * 3)
        self.assertEqual(self.paths(), ["app.py"])

    def test_fingerprints_survive_line_shifts(self):
        path = write(self.root, "a.py", "h = hashlib.md5(x)\n")
        before = {f.fingerprint for f in scan_path(self.root).findings}
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("import os\n\n\nh = hashlib.md5(x)\n")
        after = {f.fingerprint for f in scan_path(self.root).findings}
        self.assertEqual(before, after)

    def test_a_file_that_matches_on_every_line_is_capped(self):
        write(self.root, "words.py", "x = 'RSA-2048'\n" * 30000)
        result = scan_path(self.root)
        self.assertEqual(result.truncated, ["words.py"])
        self.assertLessEqual(len(result.findings), 400)


if __name__ == "__main__":
    unittest.main()
