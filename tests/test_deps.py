"""Dependency manifest parsing."""

import os
import tempfile
import unittest

from pqscan.deps import parse_manifest

FILES = {
    "requirements.txt": (
        "cryptography[ssh]>=41.0 ; python_version>'3.8'\nPyJWT==2.8.0\npyOpenSSL\n"
        "python_jose==3.3\n-r base.txt\ngit+https://example.test/x/y#egg=rsa\nrequests\n",
        {"cryptography", "PyJWT", "pyOpenSSL", "python_jose", "rsa"}),
    "pyproject.toml": (
        '[project]\nname = "app"\ndependencies = [\n  "cryptography>=41",\n  "paramiko",\n]\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\npyjwt = "*"\n',
        {"cryptography", "paramiko", "pyjwt"}),
    "package.json": (
        '{"name":"openssl","dependencies":{"node-forge":"^1.3","@noble/curves":"1.2",'
        '"express":"4"},"devDependencies":{"@types/node-forge":"1","@noble/post-quantum":"0.2"}}',
        {"node-forge", "@noble/curves", "@noble/post-quantum"}),
    "pom.xml": (
        "<project><artifactId>openssl</artifactId><dependencies><dependency>"
        "<groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId>"
        "<version>1.78</version></dependency></dependencies></project>",
        {"bcprov-jdk18on"}),
    "build.gradle": ("implementation 'org.bouncycastle:bcprov-jdk18on:1.77'\n", {"bcprov-jdk18on"}),
    "go.mod": (
        "module example.test/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/crypto v0.17.0\n"
        "\tgithub.com/golang-jwt/jwt/v5 v5.2.0\n\tgithub.com/cloudflare/circl v1.3.7 // indirect\n)\n",
        {"golang.org/x/crypto", "github.com/golang-jwt/jwt/v5", "github.com/cloudflare/circl"}),
    "Gemfile": ("source 'https://rubygems.org'\ngem 'openssl'\ngem \"jwt\", '~> 2.7'\n",
                {"openssl", "jwt"}),
    "composer.json": ('{"require":{"phpseclib/phpseclib":"^3.0","monolog/monolog":"^3"}}',
                      {"phpseclib/phpseclib"}),
    "Cargo.toml": ('[dependencies]\nrsa = "0.9"\nserde = "1"\nml-kem = { version = "0.2" }\n',
                   {"rsa", "ml-kem"}),
}


class Manifests(unittest.TestCase):
    def parse(self, name, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, name)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            return parse_manifest(path, name)

    def test_each_format(self):
        for name, (text, expected) in FILES.items():
            with self.subTest(manifest=name):
                self.assertEqual({d.library for d in self.parse(name, text)}, expected)

    def test_a_project_named_like_a_library_is_not_a_dependency(self):
        deps = self.parse("pom.xml", FILES["pom.xml"][0])
        self.assertNotIn("openssl", {d.library for d in deps})

    def test_versions_and_post_quantum_flags(self):
        deps = {d.library: d for d in self.parse("requirements.txt", FILES["requirements.txt"][0])}
        self.assertEqual(deps["PyJWT"].version, "==2.8.0")
        self.assertIn("48", deps["cryptography"].pq_path)
        cargo = {d.library: d for d in self.parse("Cargo.toml", FILES["Cargo.toml"][0])}
        self.assertTrue(cargo["ml-kem"].pqc)
        self.assertFalse(cargo["rsa"].pqc)

    def test_malformed_manifests_do_not_raise(self):
        self.assertEqual(self.parse("package.json", "{ not json"), [])
        self.assertEqual(self.parse("composer.json", "[1, 2]"), [])
        self.assertEqual(self.parse("pyproject.toml", "[project\nbroken"), [])


if __name__ == "__main__":
    unittest.main()
