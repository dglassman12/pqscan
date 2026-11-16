"""Report formats: valid, self-contained and safe to open."""

import json
import os
import re
import tempfile
import unittest

from pqscan.baseline import apply_baseline
from pqscan.cbom import render_cbom
from pqscan.htmlreport import render_html
from pqscan.report import render_badge, render_console, render_markdown
from pqscan.sarif import render_sarif
from pqscan.scanner import scan_path

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")

CRYPTO_FUNCTIONS = {"generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
                    "sign", "verify", "encapsulate", "decapsulate", "other", "unknown"}
PRIMITIVES = {"drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
              "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown"}


class Cbom(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan_path(EXAMPLES)
        cls.bom = render_cbom(cls.result)

    def test_validates_against_the_cyclonedx_schema(self):
        """v0.2 failed the schema on every component."""
        try:
            from cyclonedx.schema import SchemaVersion
            from cyclonedx.validation.json import JsonStrictValidator
        except ImportError:
            self.skipTest("pip install cyclonedx-python-lib jsonschema to run this check")
        error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(json.dumps(self.bom))
        self.assertIsNone(error, str(error))

    def test_enumerated_values(self):
        for comp in self.bom["components"]:
            props = comp.get("cryptoProperties", {}).get("algorithmProperties")
            if props:
                self.assertIn(props["primitive"], PRIMITIVES, comp["name"])
                self.assertTrue(set(props["cryptoFunctions"]) <= CRYPTO_FUNCTIONS, comp["name"])

    def test_primitives_and_levels(self):
        algo = {c["name"]: c["cryptoProperties"]["algorithmProperties"]
                for c in self.bom["components"]
                if c.get("cryptoProperties", {}).get("assetType") == "algorithm"}
        self.assertEqual(algo["AES-256"]["primitive"], "block-cipher")
        self.assertEqual(algo["AES-256"]["nistQuantumSecurityLevel"], 5)
        self.assertEqual(algo["RSA"]["nistQuantumSecurityLevel"], 0)
        self.assertEqual(algo["ML-KEM"]["primitive"], "kem")
        self.assertEqual(algo["ML-KEM"]["parameterSetIdentifier"], "768")

    def test_every_finding_is_an_occurrence(self):
        occurrences = sum(len(c.get("evidence", {}).get("occurrences", []))
                          for c in self.bom["components"]
                          if c.get("cryptoProperties", {}).get("assetType") in ("algorithm", "protocol"))
        self.assertEqual(occurrences, len(self.result.active))

    def test_unique_refs(self):
        refs = [c["bom-ref"] for c in self.bom["components"]]
        self.assertEqual(len(refs), len(set(refs)))


class Sarif(unittest.TestCase):
    def test_structure(self):
        result = scan_path(EXAMPLES)
        doc = render_sarif(result)
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))
        actionable = [f for f in result.active if f.risk != "safe"]
        self.assertEqual(len(run["results"]), len(actionable))
        for item in run["results"]:
            self.assertEqual(rule_ids[item["ruleIndex"]], item["ruleId"])
            self.assertIn(item["level"], ("error", "warning", "note"))
            region = item["locations"][0]["physicalLocation"]["region"]
            self.assertGreaterEqual(region["startLine"], 1)
            self.assertTrue(item["partialFingerprints"]["pqscan/v1"])

    def test_baseline_state(self):
        result = scan_path(EXAMPLES)
        known = {f.fingerprint for f in result.findings if f.algorithm != "RC4"}
        apply_baseline(result, known)
        states = {r["ruleId"]: r["baselineState"] for r in render_sarif(result)["runs"][0]["results"]}
        self.assertEqual(states["RC4-001"], "new")
        self.assertEqual(states["MD5-001"], "unchanged")


class HostileInput(unittest.TestCase):
    """Scanned code is untrusted: it must not be able to break or script a report."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        root = cls._tmp.name
        os.makedirs(os.path.join(root, "a|b"))
        with open(os.path.join(root, "a|b", "x`y.py"), "w") as fh:
            fh.write('h = hashlib.md5("</script><script>alert(1)</script>")  '
                     '| `tick` <img src=x onerror=alert(2)>\n')
        cls.result = scan_path(root)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_html_keeps_scanned_text_inert(self):
        html = render_html(self.result)
        self.assertEqual(len(re.findall(r"<script\b", html)), 2)      # the data block and the app
        self.assertEqual(len(re.findall(r"</script>", html)), 2)
        self.assertNotIn("<img", html)
        self.assertNotIn("innerHTML", html)
        data = re.search(r'<script type="application/json" id="data">(.*?)</script>', html, re.S)
        payload = json.loads(data.group(1))
        self.assertIn("</script>", payload["findings"][0]["s"])

    def test_html_is_self_contained(self):
        html = render_html(scan_path(EXAMPLES))
        self.assertIsNone(re.search(r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""", html))
        self.assertNotIn("@import", html)

    def test_markdown_tables_survive_pipes_and_backticks(self):
        report = render_markdown(self.result)
        row = [line for line in report.splitlines()
               if line.startswith("| high") and "y.py" in line][0]
        self.assertEqual(len(re.findall(r"(?<!\\)\|", row)), 6)      # five cells

    def test_reports_carry_the_skip_marker(self):
        for text in (render_markdown(self.result), render_html(self.result),
                     render_badge(self.result), json.dumps(render_sarif(self.result))):
            self.assertIn("pqscan-generated", text[:2048])


class Human(unittest.TestCase):
    def test_console_and_markdown_headline_numbers_agree(self):
        result = scan_path(EXAMPLES)
        console = render_console(result)
        vulnerable = sum(1 for f in result.active if f.quantum == "shor" and f.risk != "safe")
        self.assertIn("%d quantum-vulnerable usages" % vulnerable, console)
        self.assertIn("**%d uses of quantum-vulnerable" % vulnerable, render_markdown(result))
        self.assertNotIn("\033[", console)

    def test_empty_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = scan_path(tmp)
        self.assertIn("No cryptography detected", render_console(result))
        self.assertIn("No cryptographic identifiers", render_markdown(result))
        self.assertIn("no public-key crypto found", render_badge(result))
        json.dumps(render_cbom(result)), json.dumps(render_sarif(result)), render_html(result)

    def test_top_zero(self):
        report = render_markdown(scan_path(EXAMPLES), top_n=0)
        self.assertIn("## Findings (0 of", report)

    def test_badge(self):
        badge = render_badge(scan_path(EXAMPLES))
        self.assertTrue(badge.startswith("<svg "))
        self.assertRegex(badge, r"\d+% migrated")


if __name__ == "__main__":
    unittest.main()
