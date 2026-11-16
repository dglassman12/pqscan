"""Certificate and key parsing."""

import base64
import os
import unittest

from pqscan import certs
from pqscan.scanner import scan_path, scan_text

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")


# --- a tiny DER writer, so the tests need no real private keys --------------

def der(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + head + body


def seq(*parts):
    return der(0x30, b"".join(parts))


def integer(value):
    return der(0x02, value.to_bytes(value.bit_length() // 8 + 1, "big"))


def oid(dotted):
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        chunk = [p & 0x7F]
        p >>= 7
        while p:
            chunk.append(0x80 | (p & 0x7F))
            p >>= 7
        out += bytes(reversed(chunk))
    return der(0x06, out)


def pem(label, body):
    b64 = base64.b64encode(body).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return "-----BEGIN %s-----\n%s\n-----END %s-----\n" % (label, lines, label)


FAKE_MODULUS = (1 << 3071) | 0xC0FFEE | 1


class Keys(unittest.TestCase):
    def one(self, text):
        found = certs.scan_text(text)
        self.assertEqual(len(found), 1, found)
        return found[0]

    def test_pkcs1_rsa_private_key_size(self):
        body = seq(integer(0), integer(FAKE_MODULUS), integer(65537),
                   *[integer(12345)] * 6)
        obj = self.one(pem("RSA PRIVATE KEY", body))
        self.assertEqual((obj.kind, obj.key_algorithm, obj.key_bits), ("private-key", "RSA", 3072))

    def test_sec1_ec_private_key_curve(self):
        body = seq(integer(1), der(0x04, b"\x01" * 48), der(0xA0, oid("1.3.132.0.34")))
        obj = self.one(pem("EC PRIVATE KEY", body))
        self.assertEqual(obj.describe(), "Private key, EC P-384")

    def test_pkcs8_ed25519(self):
        body = seq(integer(0), seq(oid("1.3.101.112")), der(0x04, b"\x02" * 34))
        obj = self.one(pem("PRIVATE KEY", body))
        self.assertEqual((obj.rule_id, obj.key_algorithm), ("EDDSA-001", "Ed25519"))

    def test_spki_rsa_public_key(self):
        key = seq(integer(FAKE_MODULUS), integer(65537))
        body = seq(seq(oid("1.2.840.113549.1.1.1"), der(0x05, b"")), der(0x03, b"\0" + key))
        self.assertEqual(self.one(pem("PUBLIC KEY", body)).describe(), "Public key, RSA-3072")

    def test_spki_ml_kem_public_key_is_safe(self):
        body = seq(seq(oid("2.16.840.1.101.3.4.4.2")), der(0x03, b"\0" + b"\x07" * 1184))
        obj = self.one(pem("PUBLIC KEY", body))
        self.assertEqual((obj.rule_id, obj.key_algorithm), ("MLKEM-001", "ML-KEM-768"))

    def test_ssh_public_keys(self):
        def ssh_string(b):
            return len(b).to_bytes(4, "big") + b
        n = FAKE_MODULUS.to_bytes(385, "big")
        blob = ssh_string(b"ssh-rsa") + ssh_string(b"\x01\x00\x01") + ssh_string(n)
        line = "ssh-rsa %s user@host\n" % base64.b64encode(blob).decode()
        self.assertEqual(self.one(line).describe(), "SSH public key, RSA-3072")
        line = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= host\n"
        self.assertEqual(self.one(line).key_algorithm, "EC P-256")

    def test_garbage_is_ignored_not_guessed(self):
        self.assertEqual(certs.scan_text(pem("CERTIFICATE", b"\x30\x03\x02\x01\x00")), [])
        self.assertEqual(certs.scan_text("-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n"), [])
        self.assertIsNone(certs.scan_der(b"\x00\x01\x02"))

    def test_key_material_never_reaches_a_report(self):
        body = seq(integer(0), integer(FAKE_MODULUS), integer(65537), *[integer(12345)] * 6)
        text = pem("RSA PRIVATE KEY", body)
        secret = text.splitlines()[1]
        for f in scan_text(text, "server.key", "server.key"):
            for value in (f.snippet, f.detail, f.match, f.note):
                self.assertNotIn(secret[:24], value)


    def test_a_key_pasted_on_one_line_is_redacted(self):
        """Service-account JSON and .env files hold the whole PEM on one line."""
        body = seq(integer(0), integer(FAKE_MODULUS), integer(65537), *[integer(12345)] * 6)
        b64 = base64.b64encode(body).decode()
        escaped = "\\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
        line = ('{"type": "service_account", "private_key": "-----BEGIN RSA PRIVATE KEY-----\\n'
                + escaped + '\\n-----END RSA PRIVATE KEY-----\\n"}')
        hits = scan_text(line + "\n", "sa.json", "sa.json")
        self.assertTrue(hits)
        for f in hits:
            self.assertNotIn(b64[:16], f.snippet)
            self.assertNotIn(b64[200:216], f.snippet)
            self.assertIn("[redacted]", f.snippet)
        env = "JWT_SECRET=" + base64.b64encode(bytes(range(7, 71))).decode() + "  # HS256, was RS256"
        for f in scan_text(env + "\n", ".env", ".env"):
            self.assertNotIn(env[11:40], f.snippet)


class Certificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = scan_path(EXAMPLES)
        cls.by_subject = {c["subject"]: c for c in cls.result.certificates}

    def test_rsa_certificate(self):
        cert = self.by_subject["CN=api.example.test"]
        self.assertEqual((cert["key_algorithm"], cert["key_bits"]), ("RSA", 2048))
        self.assertEqual(cert["signature_algorithm"], "sha256WithRSAEncryption")
        self.assertEqual(cert["not_after"], "2034-04-08")
        self.assertFalse(cert["quantum_safe"])

    def test_ec_certificate(self):
        cert = self.by_subject["CN=gateway.example.test"]
        self.assertEqual((cert["key_algorithm"], cert["key_bits"]), ("EC P-256", 256))

    def test_sha1_signed_certificate_raises_a_second_finding(self):
        hits = [f for f in self.result.findings
                if f.path.endswith("legacy-root.example.test.crt")]
        self.assertEqual(sorted(f.algorithm for f in hits), ["RSA", "SHA-1"])
        self.assertTrue(all(f.context == "certificate" for f in hits))

    def test_post_quantum_certificate(self):
        cert = self.by_subject["CN=pq.example.test"]
        self.assertEqual(cert["key_algorithm"], "ML-DSA-65")
        self.assertTrue(cert["quantum_safe"])
        hits = [f for f in self.result.findings if f.path.endswith("pq.example.test.crt")]
        self.assertEqual([(f.algorithm, f.risk) for f in hits], [("ML-DSA", "safe")])

    def test_der_certificate_file(self):
        import tempfile
        with open(os.path.join(EXAMPLES, "deploy", "certs", "api.example.test.crt")) as fh:
            body = "".join(line for line in fh.read().splitlines() if "-----" not in line)
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "api.der"), "wb") as fh:
                fh.write(base64.b64decode(body))
            result = scan_path(tmp)
        self.assertEqual([c["subject"] for c in result.certificates], ["CN=api.example.test"])
        self.assertEqual(result.findings[0].context, "certificate")


if __name__ == "__main__":
    unittest.main()
