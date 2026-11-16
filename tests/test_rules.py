"""Detection rules: what must be found, what must not, and how it is labelled."""

import os
import unittest

from pqscan.rules import RULES
from pqscan.scanner import _scan_text, scan_text

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


def found(line, name="a.py", policy="nist"):
    """{algorithm: risk} for one line of source, mentions excluded."""
    return {f.algorithm: f.risk for f in scan_text(line + "\n", name, name, policy)
            if not f.mention}


class Detection(unittest.TestCase):
    CASES = [
        # (file name, line, algorithm, risk)
        ("a.py", "key = ec.generate_private_key(ec.SECP256R1())",
         "Elliptic curve (scheme not stated)", "critical"),
        ("A.java", 'KeyPairGenerator.getInstance("EC")',
         "Elliptic curve (scheme not stated)", "critical"),
        ("a.go", "tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,", "ECDH", "critical"),
        ("a.go", "tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,", "RSA", "critical"),
        ("a.go", "tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,", "AES-128", "low"),
        ("a.conf", "ssl_ciphers DHE-RSA-AES256-GCM-SHA384;",
         "Diffie-Hellman (finite field)", "critical"),
        ("A.java", 'Signature.getInstance("SHA256withRSA")', "RSA", "critical"),
        ("A.java", 'Signature.getInstance("SHA1withRSA")', "SHA-1", "high"),
        ("a.c", "EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);", "RSA", "critical"),
        ("a.js", "jwt.sign(payload, key, { algorithm: 'RS256' })", "RSA", "critical"),
        ("a.js", "jwt.sign(payload, key, { algorithm: 'ES256' })", "ECDSA", "critical"),
        ("a.go", "priv, err := rsa.GenerateKey(rand.Reader, 2048)", "RSA", "critical"),
        ("a.py", "X448PrivateKey.generate()", "X25519 / X448", "critical"),
        ("a.py", "Ed25519PrivateKey.generate()", "EdDSA", "critical"),
        ("a.py", "from Crypto.Cipher import DES3", "3DES", "high"),
        ("a.sh", "openssl enc -des-ede3-cbc", "3DES", "high"),
        ("a.py", "cipher = des.new(key, des.MODE_ECB)", "DES", "high"),
        ("A.java", 'Cipher.getInstance("RC4")', "RC4", "high"),
        ("a.sh", "sha1sum file.iso", "SHA-1", "high"),
        ("A.java", 'Mac.getInstance("HmacSHA1")', "SHA-1", "high"),
        ("a.go", "tls.TLS_RSA_WITH_AES_128_CBC_SHA,", "SHA-1", "high"),
        ("a.sh", "md5sum file.iso", "MD5", "high"),
        ("a.py", "cipher = AES_128_GCM", "AES-128", "low"),
        ("a.py", "Cipher(algorithms.AES(key), modes.CBC(iv))",
         "AES (key size not stated)", "info"),
        ("a.conf", "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;", "TLS 1.0 / 1.1", "high"),
        ("a.py", "hashlib.sha384(data)", "SHA-384", "safe"),
        ("a.py", "hashlib.sha256(data)", "SHA-256", "safe"),
        ("a.py", "kem = ML_KEM_768", "ML-KEM", "safe"),
        ("a.py", "oqs.KeyEncapsulation('mlkem768')", "ML-KEM", "safe"),
        ("a.py", 'oqs.KeyEncapsulation("Kyber768")', "ML-KEM", "safe"),
        ("a.conf", "ssl_ecdh_curve X25519MLKEM768;", "Hybrid PQ key exchange", "safe"),
    ]

    def test_cases(self):
        for name, line, algorithm, risk in self.CASES:
            with self.subTest(line=line, algorithm=algorithm):
                self.assertEqual(found(line, name).get(algorithm), risk)


class PostQuantumIsNotMislabelled(unittest.TestCase):
    """v0.2 reported ML-DSA and SLH-DSA as critical DSA."""

    def test_ml_dsa(self):
        self.assertEqual(found('alg = "ML-DSA-65"'), {"ML-DSA": "safe"})

    def test_slh_dsa(self):
        self.assertEqual(found('alg = "SLH-DSA-SHA2-128s"'), {"SLH-DSA": "safe"})

    def test_hybrid_is_not_plain_x25519(self):
        self.assertEqual(found('group = "X25519MLKEM768"'),
                         {"Hybrid PQ key exchange": "safe"})

    def test_classical_fallback_next_to_hybrid_is_still_reported(self):
        got = found("ssl_ecdh_curve X25519MLKEM768:X25519:secp384r1;", "nginx.conf")
        self.assertEqual(got.get("Hybrid PQ key exchange"), "safe")
        self.assertEqual(got.get("X25519 / X448"), "critical")
        self.assertEqual(got.get("Elliptic curve (scheme not stated)"), "critical")

    def test_real_dsa_still_found(self):
        self.assertEqual(found('KeyPairGenerator.getInstance("DSA")', "A.java"),
                         {"DSA": "critical"})


class FalsePositives(unittest.TestCase):
    LINES = [
        ("a.py", 'city = "DES MOINES, IA"'),
        ("a.py", "team = 'dsa'"),
        ("a.py", "course = 'DSA'  # data structures and algorithms"),
        ("a.py", "topics = ['dsa', 'algorithms', 'graphs']"),
        ("a.sh", "DH_HOME=/opt/datahub"),
        ("a.yml", "author: rsa <rsa@example.com>"),
        ("a.py", 'part = "P-256"'),
        ("a.js", "const descriptor = designSystem.desktop;"),
        ("a.py", 'x = "mulle-kybernetik"'),
        ("a.py", "PROTOCOL_SSLv23 = 2"),
        ("a.go", "var x448 uint64"),
        ("a.go", "err = marshalECDHPrivateKeyHelper(k)"),
    ]

    def test_non_crypto_lines(self):
        for name, line in self.LINES:
            with self.subTest(line=line):
                got = found(line, name)
                got.pop("ECDH", None)          # the last line is real ECDH
                self.assertEqual(got, {})

    def test_go_raw_socket_address_is_not_rsa(self):
        code = ("func recv(o *operation) {\n\tif o.rsa == nil {\n"
                "\t\to.rsa = new(syscall.RawSockaddrAny)\n\t}\n"
                "\tsa, _ := o.rsa.Sockaddr()\n}\n")
        self.assertEqual(scan_text(code, "fd_windows.go", "fd_windows.go"), [])

    def test_short_tokens_need_crypto_vocabulary_close_by(self):
        far = "x = rsa\n" + "\n" * 8 + "import ssl\n"
        self.assertEqual(scan_text(far, "a.py", "a.py"), [])
        self.assertEqual(found("alg = 'rsa'"), {"RSA": "critical"})
        self.assertEqual(found("  key_type: rsa", "a.yml"), {"RSA": "critical"})
        config = "[tls]\nenabled = true\n\n\n\n\n[legacy]\nmode = DES\n"
        self.assertEqual({f.algorithm for f in scan_text(config, "app.ini", "app.ini")}, {"DES"})

    def test_base64_cannot_spell_an_algorithm(self):
        blob = "Kc323vGBEqzTmouAECnVceyQqmd5yqdsSiqLQISBL29aUW4U"      # ...md5...
        self.assertEqual(found("token = '%s'" % blob), {})
        der = "MIIBxTCCAWugAwIBAgIJAJZAUtw5ccb1MAoGCCqGSM49BAMCMCUxDDAKBgNVRSAx"
        self.assertEqual(found('cert = "%s"' % der), {})
        record = "pkg/data.py,sha256=3to_O_Jeo5CHdlHmkN398B_i9pi5YAKUbM1mD5Zm_jc,1652"
        self.assertEqual(found(record, "RECORD"), {"SHA-256": "safe"})
        sri = 'integrity="sha512-Kc323vGBEqzTmouAECnVceyQqyqdsSiqLQISBL29aUW4U/M7pSPA/gEUZQqv1cwx4Onmd5=="'
        self.assertEqual(found(sri, "a.html"), {"SHA-512": "safe"})

    def test_long_identifiers_are_not_mistaken_for_base64(self):
        name = "func TestHandshakeClientECDHERSAChaCha20Poly1305SHA256(t *testing.T) {"
        got = found(name, "a_test.go")
        self.assertEqual(got.get("ECDH"), "critical")
        self.assertEqual(got.get("ChaCha20"), "safe")
        self.assertEqual(got.get("SHA-256"), "safe")


class Context(unittest.TestCase):
    def test_comments_and_docs_are_mentions(self):
        cases = [
            ("a.py", "x = 1  # RSA-2048 is broken by Shor's algorithm"),
            ("a.go", "// uses ECDSA"),
            ("a.java", " * Signs tokens with SHA256withRSA."),
            ("README.md", "We use RSA-2048 and SHA-1."),
            ("a.sql", "-- md5 of the row"),
        ]
        for name, line in cases:
            with self.subTest(name=name):
                text = ("/**\n%s\n */\n" % line) if name == "a.java" else line + "\n"
                hits = scan_text(text, name, name)
                self.assertTrue(hits, "nothing found")
                self.assertTrue(all(f.mention for f in hits))

    def test_code_before_a_comment_is_not_a_mention(self):
        hits = scan_text("h = hashlib.md5(x)  # legacy\n", "a.py", "a.py")
        self.assertEqual([(f.algorithm, f.mention) for f in hits], [("MD5", False)])

    def test_url_is_not_a_comment(self):
        hits = scan_text('u = "https://x.test/rsa-2048"\n', "a.js", "a.js")
        self.assertEqual([(f.algorithm, f.mention) for f in hits], [("RSA", False)])

    def test_config_context(self):
        hits = scan_text("ssl_ciphers RC4-SHA;\n", "nginx.conf", "nginx.conf")
        self.assertEqual({f.context for f in hits}, {"config"})

    def test_inline_ignore(self):
        self.assertEqual(found("h = hashlib.md5(x)  # pqscan: ignore"), {})

    def test_parameters_are_kept_as_detail(self):
        hits = scan_text("KexAlgorithms ecdh-sha2-nistp256\n", "sshd_config", "sshd_config")
        ecdh = [f for f in hits if f.algorithm == "ECDH"][0]
        self.assertEqual(ecdh.detail, "nistp256")


class Policy(unittest.TestCase):
    def test_cnsa2_is_stricter(self):
        self.assertEqual(found("c = AES_128_GCM")["AES-128"], "low")
        self.assertEqual(found("c = AES_128_GCM", policy="cnsa2")["AES-128"], "high")
        self.assertEqual(found('k = "ML-KEM-768"', policy="cnsa2")["ML-KEM"], "medium")
        self.assertEqual(found('k = "ML-KEM-1024"', policy="cnsa2")["ML-KEM"], "safe")


class Prefilter(unittest.TestCase):
    """The hint prefilter must never change what is found."""

    def _texts(self):
        for _name, line, _a, _r in Detection.CASES:
            yield "a.txt", line + "\n"
        for dirpath, _dirs, files in os.walk(EXAMPLES):
            for name in files:
                with open(os.path.join(dirpath, name), encoding="utf-8", errors="ignore") as fh:
                    yield name, fh.read()

    def test_same_result_with_and_without(self):
        for name, text in self._texts():
            with self.subTest(name=name):
                fast = _scan_text(text, name, name, "nist", prefilter=True)[0]
                slow = _scan_text(text, name, name, "nist", prefilter=False)[0]
                key = lambda f: (f.line, f.col, f.algorithm, f.match, f.detail)
                self.assertEqual([key(f) for f in fast], [key(f) for f in slow])

    def test_every_rule_has_hints(self):
        for rule in RULES:
            self.assertTrue(rule.hints, rule.id)
            self.assertTrue(all(h == h.lower() for h in rule.hints), rule.id)


if __name__ == "__main__":
    unittest.main()
