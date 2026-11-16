"""Command line behaviour and exit codes."""

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest

from pqscan.cli import main

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(argv))
        except SystemExit as exc:            # argparse errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class ExitCodes(unittest.TestCase):
    def test_plain_scan(self):
        code, out, _ = run(EXAMPLES, "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("quantum-vulnerable usages", out)

    def test_fail_on(self):
        self.assertEqual(run(EXAMPLES, "-q", "--fail-on", "critical")[0], 1)
        self.assertEqual(run(EXAMPLES, "-q", "--fail-on-critical")[0], 1)
        self.assertEqual(run(os.path.join(EXAMPLES, "pq"), "-q", "--fail-on", "low")[0], 0)

    def test_bad_arguments(self):
        self.assertEqual(run("/no/such/dir")[0], 2)
        self.assertEqual(run(os.path.join(EXAMPLES, "requirements.txt"))[0], 2)
        self.assertEqual(run(EXAMPLES, "--top", "-5")[0], 2)
        self.assertEqual(run(EXAMPLES, "--baseline", "/no/such/file")[0], 2)
        self.assertEqual(run()[0], 2)

    def test_list_rules(self):
        code, out, _ = run("--list-rules")
        self.assertEqual(code, 0)
        self.assertIn("ML-KEM", out)


class Baseline(unittest.TestCase):
    def test_only_new_findings_fail_the_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            shutil.copytree(EXAMPLES, repo)
            baseline = os.path.join(tmp, "baseline.json")

            self.assertEqual(run(repo, "-q", "--write-baseline", baseline)[0], 0)
            self.assertEqual(run(repo, "-q", "--baseline", baseline, "--fail-on", "low")[0], 0)

            with open(os.path.join(repo, "new_feature.py"), "w") as fh:
                fh.write("key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
            code, _, err = run(repo, "--no-color", "--baseline", baseline, "--fail-on", "critical")
            self.assertEqual(code, 1)
            self.assertIn("1 new finding", err)

    def test_a_json_findings_file_works_as_a_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            findings = os.path.join(tmp, "findings.json")
            self.assertEqual(run(EXAMPLES, "-q", "--json", findings)[0], 0)
            with open(findings) as fh:
                self.assertTrue(json.load(fh)["findings"])
            self.assertEqual(run(EXAMPLES, "-q", "--baseline", findings, "--fail-on", "low")[0], 0)


class Flags(unittest.TestCase):
    def test_include_mentions_changes_the_count(self):
        def total(*extra):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "f.json")
                run(EXAMPLES, "-q", "--json", path, *extra)
                with open(path) as fh:
                    data = json.load(fh)
            return sum(1 for f in data["findings"] if not f["mention"]), len(data["findings"])
        real, everything = total()
        self.assertGreater(everything, real)

    def test_policy(self):
        code, out, _ = run(EXAMPLES, "--no-color", "--policy", "cnsa2")
        self.assertEqual(code, 0)
        self.assertIn("policy: cnsa2", out)


if __name__ == "__main__":
    unittest.main()
