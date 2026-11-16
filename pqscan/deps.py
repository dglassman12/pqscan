"""
Dependency manifest parsing.

Source-code scanning misses a lot of real cryptography, because most crypto
lives inside libraries rather than in the application's own code. This module
reads the common manifest formats and records which cryptographic libraries
a project depends on.

A dependency is not a vulnerability. It is an inventory item: "this project
pulls in a library that implements RSA/ECC, so it needs review."
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:                                    # Python 3.11+
    import tomllib as _toml
except ImportError:                     # pragma: no cover - 3.9 / 3.10
    _toml = None

# (ecosystem, normalised name) -> (note, is a post-quantum library)
_LIBS: Dict[Tuple[str, str], Tuple[str, bool]] = {}


def _add(ecosystem: str, names: str, note: str, pqc: bool = False) -> None:
    for name in names.split():
        _LIBS[(ecosystem, name)] = (note, pqc)


# Python (names normalised per PEP 503: lowercase, runs of -_. become -)
_add("pypi", "cryptography", "Python crypto bindings: RSA, ECC, AES, hashes")
_add("pypi", "pycryptodome pycryptodomex pycrypto", "Python crypto library: RSA, ECC, AES, DES")
_add("pypi", "pyopenssl m2crypto", "OpenSSL bindings")
_add("pypi", "paramiko asyncssh", "SSH implementation: RSA / ECDSA / Ed25519 keys")
_add("pypi", "pyjwt python-jose authlib jwcrypto josepy", "JOSE / JWT: usually RSA or ECDSA signed")
_add("pypi", "rsa", "Pure-Python RSA")
_add("pypi", "ecdsa", "Pure-Python ECDSA")
_add("pypi", "pynacl", "libsodium bindings: Ed25519, X25519")
_add("pypi", "pyotp", "TOTP: HMAC-SHA1")
_add("pypi", "python-gnupg pgpy", "OpenPGP: RSA / ECC keys")
_add("pypi", "certifi truststore", "CA bundle: the trust anchors are RSA / ECC")
_add("pypi", "liboqs-python pqcrypto kyber-py dilithium-py",
     "Post-quantum algorithms", pqc=True)

# JavaScript
_add("npm", "crypto-js", "JavaScript crypto library: AES, DES, MD5, SHA-1")
_add("npm", "node-forge", "TLS, RSA and X.509 in JavaScript")
_add("npm", "jsonwebtoken jose jws jwa", "JOSE / JWT: usually RSA or ECDSA signed")
_add("npm", "elliptic secp256k1 @noble/curves @noble/secp256k1 @noble/ed25519",
     "Elliptic-curve crypto")
_add("npm", "tweetnacl libsodium-wrappers sodium-native", "NaCl: Ed25519, X25519")
_add("npm", "openpgp", "OpenPGP: RSA / ECC keys")
_add("npm", "node-rsa jsrsasign jsencrypt", "RSA in JavaScript")
_add("npm", "ssh2", "SSH implementation")
_add("npm", "md5 sha1 js-sha1", "Classically broken hash")
_add("npm", "@noble/post-quantum mlkem crystals-kyber",
     "Post-quantum algorithms", pqc=True)

# Java (Maven artifactId)
_add("maven", "bcprov-jdk18on bcprov-jdk15on bcprov-jdk15to18 bcprov-lts8on bc-fips",
     "Bouncy Castle provider")
_add("maven", "bcpkix-jdk18on bcpkix-jdk15on bctls-jdk18on", "Bouncy Castle PKIX / TLS")
_add("maven", "nimbus-jose-jwt jjwt jjwt-api java-jwt jose4j", "JOSE / JWT")
_add("maven", "jsch sshj", "SSH implementation")
_add("maven", "tink conscrypt-openjdk", "Crypto provider")
_add("maven", "bcpqc-jdk18on bcpqc-jdk15on", "Bouncy Castle post-quantum provider", pqc=True)

# Go
_add("go", "golang.org/x/crypto", "Go supplementary crypto packages")
_add("go", "github.com/golang-jwt/jwt github.com/dgrijalva/jwt-go github.com/go-jose/go-jose "
     "github.com/lestrrat-go/jwx", "JOSE / JWT")
_add("go", "github.com/cloudflare/circl", "CIRCL: includes post-quantum KEMs and signatures", pqc=True)
_add("go", "github.com/open-quantum-safe/liboqs-go", "Post-quantum algorithms", pqc=True)

# Ruby
_add("rubygems", "openssl", "OpenSSL bindings")
_add("rubygems", "jwt json-jwt", "JOSE / JWT")
_add("rubygems", "rbnacl ed25519 x25519", "Curve25519 crypto")
_add("rubygems", "net-ssh", "SSH implementation")
_add("rubygems", "bcrypt-pbkdf", "OpenSSH key decryption")

# PHP (vendor/package)
_add("composer", "phpseclib/phpseclib", "PHP crypto library: RSA, ECC")
_add("composer", "firebase/php-jwt lcobucci/jwt web-token/jwt-framework", "JOSE / JWT")
_add("composer", "paragonie/sodium_compat paragonie/halite", "libsodium: Ed25519, X25519")
_add("composer", "defuse/php-encryption", "Symmetric encryption")

# Rust
_add("cargo", "rsa", "Pure-Rust RSA")
_add("cargo", "ring aws-lc-rs openssl boring", "General crypto: RSA, ECC, AES")
_add("cargo", "rustls native-tls", "TLS implementation")
_add("cargo", "ed25519-dalek x25519-dalek curve25519-dalek p256 p384 k256 ecdsa",
     "Elliptic-curve crypto")
_add("cargo", "jsonwebtoken", "JOSE / JWT")
_add("cargo", "md-5 sha1", "Classically broken hash")
_add("cargo", "ml-kem ml-dsa slh-dsa pqcrypto oqs pqc_kyber fips203 fips204",
     "Post-quantum algorithms", pqc=True)

# Where a mainstream library already ships the NIST algorithms, say so: the
# first migration step is often "upgrade what you already depend on".
# Versions were checked against each project's release notes in November 2026.
_OPENSSL = "Uses the linked OpenSSL; 3.5 and later provide ML-KEM and ML-DSA"
_BC = "ML-KEM, ML-DSA and SLH-DSA from Bouncy Castle 1.79"
_PQ_PATH: Dict[Tuple[str, str], str] = {
    ("pypi", "cryptography"): "ML-KEM and ML-DSA from version 48",
    ("pypi", "pyopenssl"): _OPENSSL,
    ("pypi", "m2crypto"): _OPENSSL,
    ("rubygems", "openssl"): _OPENSSL,
    ("cargo", "openssl"): _OPENSSL,
    ("maven", "bcprov-jdk18on"): _BC,
    ("maven", "bcprov-jdk15to18"): _BC,
    ("maven", "bcpkix-jdk18on"): _BC,
    ("maven", "bctls-jdk18on"): "Hybrid and ML-KEM TLS key exchange from Bouncy Castle 1.81",
    ("go", "golang.org/x/crypto"): "Go 1.24 and later ship crypto/mlkem in the standard library",
}

# file name -> (ecosystem, parser name)
MANIFESTS = {
    "requirements.txt": ("pypi", "requirements"),
    "requirements-dev.txt": ("pypi", "requirements"),
    "requirements-test.txt": ("pypi", "requirements"),
    "requirements.in": ("pypi", "requirements"),
    "constraints.txt": ("pypi", "requirements"),
    "pyproject.toml": ("pypi", "pyproject"),
    "Pipfile": ("pypi", "pipfile"),
    "package.json": ("npm", "package_json"),
    "pom.xml": ("maven", "pom"),
    "build.gradle": ("maven", "gradle"),
    "build.gradle.kts": ("maven", "gradle"),
    "go.mod": ("go", "go_mod"),
    "Gemfile": ("rubygems", "gemfile"),
    "composer.json": ("composer", "composer"),
    "Cargo.toml": ("cargo", "cargo"),
}

MAX_MANIFEST_BYTES = 2_000_000


@dataclass
class Dependency:
    path: str
    ecosystem: str
    library: str
    version: str
    note: str
    pqc: bool = False
    pq_path: str = ""        # how to get post-quantum algorithms from this library


def is_manifest(filename: str) -> bool:
    if filename in MANIFESTS:
        return True
    return filename.startswith("requirements") and filename.endswith(".txt")


def _normalise(ecosystem: str, name: str) -> str:
    name = name.strip().lower()
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name)
    return name


def _lookup(ecosystem: str, name: str) -> Optional[Tuple[str, bool]]:
    key = _normalise(ecosystem, name)
    hit = _LIBS.get((ecosystem, key))
    if hit:
        return hit
    if ecosystem == "go":
        # versioned module paths: github.com/golang-jwt/jwt/v5
        base = re.sub(r"/v\d+$", "", key)
        return _LIBS.get((ecosystem, base))
    if ecosystem == "npm" and key.startswith("@types/"):
        return None
    return None


# ----------------------------------------------------------------------
# Parsers. Each returns a list of (name, version) pairs.
# ----------------------------------------------------------------------

_REQ_SPLIT = re.compile(r"[<>=!~\[;@ ]")


def _requirement(spec: str) -> Optional[Tuple[str, str]]:
    """Split one PEP 508 requirement string into (name, version spec)."""
    spec = spec.strip()
    if not spec or spec.startswith(("#", "-")):
        return None
    egg = re.search(r"[#&]egg=([A-Za-z0-9_.-]+)", spec)
    if egg:
        return egg.group(1), ""
    spec = spec.split("#", 1)[0].strip()
    name = _REQ_SPLIT.split(spec, maxsplit=1)[0]
    if not name or "/" in name or ":" in name:
        return None
    rest = spec[len(name):]
    rest = re.sub(r"^\[[^\]]*\]", "", rest.strip())
    version = rest.split(";", 1)[0].strip()
    return name, version


def _parse_requirements(text: str):
    out = []
    for line in text.splitlines():
        item = _requirement(line)
        if item:
            out.append(item)
    return out


def _poetry_version(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return str(value.get("version", ""))
    return ""


def _parse_pyproject(text: str):
    out = []
    if _toml is not None:
        try:
            data = _toml.loads(text)
        except Exception:
            data = None
        if data is not None:
            project = data.get("project") or {}
            specs = list(project.get("dependencies") or [])
            for group in (project.get("optional-dependencies") or {}).values():
                specs.extend(group or [])
            for group in (data.get("dependency-groups") or {}).values():
                specs.extend(s for s in (group or []) if isinstance(s, str))
            for spec in specs:
                item = _requirement(spec) if isinstance(spec, str) else None
                if item:
                    out.append(item)
            poetry = ((data.get("tool") or {}).get("poetry") or {})
            tables = [poetry.get("dependencies") or {},
                      poetry.get("dev-dependencies") or {}]
            for group in (poetry.get("group") or {}).values():
                tables.append((group or {}).get("dependencies") or {})
            for table in tables:
                for name, value in table.items():
                    if name.lower() != "python":
                        out.append((name, _poetry_version(value)))
            return out
    # Fallback without a TOML parser: quoted requirement strings, and
    # `name = "version"` lines.
    for m in re.finditer(r"^[ \t]*[\"']([A-Za-z0-9][A-Za-z0-9_.-]*)[ \t]*([^\"']*)[\"'],?[ \t]*$",
                         text, re.M):
        out.append((m.group(1), m.group(2).strip()))
    for m in re.finditer(r"^[ \t]*([A-Za-z0-9][A-Za-z0-9_.-]*)[ \t]*=[ \t]*[\"']([^\"']*)[\"']",
                         text, re.M):
        out.append((m.group(1), m.group(2)))
    return out


def _parse_pipfile(text: str):
    out = []
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        if section in ("packages", "dev-packages") and "=" in line:
            name, value = line.split("=", 1)
            out.append((name.strip().strip("\"'"), value.strip().strip("\"'")))
    return out


def _parse_package_json(text: str):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    if not isinstance(data, dict):
        return out
    for section in ("dependencies", "devDependencies", "peerDependencies",
                    "optionalDependencies"):
        table = data.get(section) or {}
        if isinstance(table, dict):
            out.extend((name, str(version)) for name, version in table.items())
    return out


def _parse_pom(text: str):
    out = []
    for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
        artifact = re.search(r"<artifactId>\s*([^<\s]+)\s*</artifactId>", block)
        version = re.search(r"<version>\s*([^<\s]+)\s*</version>", block)
        if artifact:
            out.append((artifact.group(1), version.group(1) if version else ""))
    return out


def _parse_gradle(text: str):
    out = []
    for m in re.finditer(r"[\"']([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)(?::([^\"'@]+))?[\"']", text):
        out.append((m.group(2), m.group(3) or ""))
    return out


def _parse_go_mod(text: str):
    out = []
    in_block = False
    for line in text.splitlines():
        line = line.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            parts = line[len("require "):].split()
        elif in_block:
            parts = line.split()
        else:
            continue
        if parts:
            out.append((parts[0], parts[1] if len(parts) > 1 else ""))
    return out


def _parse_gemfile(text: str):
    out = []
    for m in re.finditer(r"^[ \t]*gem[ \t]+['\"]([^'\"]+)['\"](?:[ \t]*,[ \t]*['\"]([^'\"]+)['\"])?",
                         text, re.M):
        out.append((m.group(1), m.group(2) or ""))
    return out


def _parse_composer(text: str):
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    if not isinstance(data, dict):
        return out
    for section in ("require", "require-dev"):
        table = data.get(section) or {}
        if isinstance(table, dict):
            out.extend((name, str(version)) for name, version in table.items())
    return out


def _parse_cargo(text: str):
    out = []
    if _toml is not None:
        try:
            data = _toml.loads(text)
        except Exception:
            data = None
        if data is not None:
            tables = [data.get(k) or {} for k in
                      ("dependencies", "dev-dependencies", "build-dependencies")]
            tables.append(((data.get("workspace") or {}).get("dependencies")) or {})
            for target in (data.get("target") or {}).values():
                tables.append((target or {}).get("dependencies") or {})
            for table in tables:
                for name, value in table.items():
                    out.append((name, _poetry_version(value)))
            return out
    section = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        if section.endswith("dependencies") and "=" in line:
            name, value = line.split("=", 1)
            version = re.search(r"[\"']([^\"']+)[\"']", value)
            out.append((name.strip(), version.group(1) if version else ""))
    return out


_PARSERS = {
    "requirements": _parse_requirements,
    "pyproject": _parse_pyproject,
    "pipfile": _parse_pipfile,
    "package_json": _parse_package_json,
    "pom": _parse_pom,
    "gradle": _parse_gradle,
    "go_mod": _parse_go_mod,
    "gemfile": _parse_gemfile,
    "composer": _parse_composer,
    "cargo": _parse_cargo,
}


def parse_manifest(full_path: str, rel_path: str) -> List[Dependency]:
    """Return the cryptographic libraries declared in one manifest file."""
    name = os.path.basename(full_path)
    ecosystem, parser = MANIFESTS.get(name, ("pypi", "requirements"))
    try:
        if os.path.getsize(full_path) > MAX_MANIFEST_BYTES:
            return []
        with open(full_path, "r", encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
    except OSError:
        return []

    found: List[Dependency] = []
    seen = set()
    for lib, version in _PARSERS[parser](text):
        hit = _lookup(ecosystem, lib)
        if not hit:
            continue
        key = _normalise(ecosystem, lib)
        if key in seen:
            continue
        seen.add(key)
        found.append(Dependency(path=rel_path, ecosystem=ecosystem, library=lib,
                                version=version.strip(), note=hit[0], pqc=hit[1],
                                pq_path=_PQ_PATH.get((ecosystem, key), "")))
    return sorted(found, key=lambda d: d.library.lower())


def scan_manifests(root: str) -> List[Dependency]:
    """Walk `root` and return every cryptographic dependency (kept for
    backwards compatibility; the scanner does this in its own walk)."""
    found: List[Dependency] = []
    skip = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv",
            "dist", "build", "target"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip]
        for name in filenames:
            if is_manifest(name):
                full = os.path.join(dirpath, name)
                found.extend(parse_manifest(full, os.path.relpath(full, root)))
    return sorted(found, key=lambda d: (d.path, d.library.lower()))
