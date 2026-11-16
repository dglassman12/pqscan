"""
Certificate and key parsing, standard library only.

Regex rules can say "this file mentions RSA". They cannot say "this is a
2048-bit RSA certificate for api.example.com, signed with SHA-1, valid until
2034". That needs the actual ASN.1, so this module carries a small DER reader
that understands just enough X.509, PKCS#1, PKCS#8, SEC1 and OpenSSH key
formats to pull out the algorithm, key size and validity.

Private key bytes are never stored or returned; only the algorithm and size.
Anything that fails to parse is ignored rather than guessed at.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

PEM_RE = re.compile(
    r"-----BEGIN ([A-Z0-9 ]+)-----\r?\n?(.*?)-----END \1-----", re.S
)
SSH_PUB_RE = re.compile(
    r"(?<![A-Za-z0-9-])(ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521))"
    r"[ \t]+(AAAA[A-Za-z0-9+/]+={0,2})"
)

OID_NAMES = {
    # public key algorithms
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.840.10040.4.1": "DSA",
    "1.2.840.113549.1.3.1": "dhKeyAgreement",
    "1.2.840.10046.2.1": "dhpublicnumber",
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    # signature algorithms
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.10040.4.3": "dsa-with-SHA1",
    "2.16.840.1.101.3.4.3.2": "dsa-with-SHA256",
    # post-quantum (FIPS 203 / 204 / 205)
    "2.16.840.1.101.3.4.4.1": "ML-KEM-512",
    "2.16.840.1.101.3.4.4.2": "ML-KEM-768",
    "2.16.840.1.101.3.4.4.3": "ML-KEM-1024",
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}
for _i in range(20, 32):
    OID_NAMES["2.16.840.1.101.3.4.3.%d" % _i] = "SLH-DSA"

CURVES = {
    "1.2.840.10045.3.1.1": ("P-192", 192),
    "1.3.132.0.33": ("P-224", 224),
    "1.2.840.10045.3.1.7": ("P-256", 256),
    "1.3.132.0.34": ("P-384", 384),
    "1.3.132.0.35": ("P-521", 521),
    "1.3.132.0.10": ("secp256k1", 256),
    "1.3.36.3.3.2.8.1.1.7": ("brainpoolP256r1", 256),
    "1.3.36.3.3.2.8.1.1.11": ("brainpoolP384r1", 384),
    "1.3.36.3.3.2.8.1.1.13": ("brainpoolP512r1", 512),
}

# public key algorithm name -> (rule id, display algorithm)
KEY_RULES = {
    "rsaEncryption": "RSA-001",
    "RSASSA-PSS": "RSA-002",
    "id-ecPublicKey": "ECDSA-001",
    "DSA": "DSA-001",
    "dhKeyAgreement": "DH-001",
    "dhpublicnumber": "DH-001",
    "X25519": "ECDH-002",
    "X448": "ECDH-002",
    "Ed25519": "EDDSA-001",
    "Ed448": "EDDSA-001",
    "ML-KEM-512": "MLKEM-001",
    "ML-KEM-768": "MLKEM-001",
    "ML-KEM-1024": "MLKEM-001",
    "ML-DSA-44": "MLDSA-001",
    "ML-DSA-65": "MLDSA-001",
    "ML-DSA-87": "MLDSA-001",
    "SLH-DSA": "SLHDSA-001",
}

SSH_RULES = {
    "ssh-rsa": "RSA-002",
    "ssh-dss": "DSA-001",
    "ssh-ed25519": "EDDSA-001",
}


@dataclass
class CryptoObject:
    """A certificate or key found in a file."""
    line: int
    kind: str                 # certificate | private-key | public-key | ssh-public-key
    rule_id: str              # rule describing the key algorithm
    key_algorithm: str        # "RSA", "EC P-256", "Ed25519", "ML-DSA-65" ...
    key_bits: Optional[int] = None
    signature_algorithm: str = ""
    weak_signature_hash: str = ""   # "SHA-1" or "MD5" when the cert is signed with one
    subject: str = ""
    issuer: str = ""
    not_before: str = ""
    not_after: str = ""
    self_signed: bool = False
    encrypted: bool = False

    def describe(self) -> str:
        size = self.key_algorithm
        if self.key_bits and str(self.key_bits) not in size:
            size = "%s-%d" % (size, self.key_bits)
        if self.kind == "certificate":
            parts = ["X.509 certificate", size]
            if self.subject:
                parts.insert(1, self.subject)
            if self.signature_algorithm:
                parts.append("signed with " + self.signature_algorithm)
            if self.not_after:
                parts.append("expires " + self.not_after)
            if self.self_signed:
                parts.append("self-signed")
            return ", ".join(parts)
        label = {
            "private-key": "Private key",
            "public-key": "Public key",
            "ssh-public-key": "SSH public key",
        }[self.kind]
        if self.encrypted:
            return "%s (encrypted; algorithm not readable)" % label
        return "%s, %s" % (label, size)


# ----------------------------------------------------------------------
# Minimal DER reader
# ----------------------------------------------------------------------

class DerError(ValueError):
    pass


def _tlv(data: bytes, pos: int) -> Tuple[int, int, int]:
    """Return (tag, value_start, value_end) for the element at pos."""
    if pos + 2 > len(data):
        raise DerError("truncated")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise DerError("multi-byte tag")
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise DerError("bad length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(data):
        raise DerError("length past end")
    return tag, pos, end


def _children(data: bytes, start: int, end: int) -> List[Tuple[int, int, int]]:
    out = []
    pos = start
    while pos < end:
        tag, vs, ve = _tlv(data, pos)
        out.append((tag, vs, ve))
        pos = ve
    return out


def _oid(raw: bytes) -> str:
    if not raw:
        raise DerError("empty OID")
    first = raw[0]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _uint_bits(raw: bytes) -> int:
    return int.from_bytes(raw, "big").bit_length()


def _time(tag: int, raw: bytes) -> str:
    text = raw.decode("ascii", "replace")
    try:
        if tag == 0x17:      # UTCTime YYMMDDhhmmssZ
            year = int(text[:2])
            year += 2000 if year < 50 else 1900
            rest = text[2:]
        else:                # GeneralizedTime YYYYMMDDhhmmssZ
            year = int(text[:4])
            rest = text[4:]
        return "%04d-%02d-%02d" % (year, int(rest[:2]), int(rest[2:4]))
    except ValueError:
        return ""


_NAME_ATTRS = {"2.5.4.3": "CN", "2.5.4.10": "O", "2.5.4.11": "OU"}


def _name(data: bytes, start: int, end: int) -> str:
    found = {}
    for tag, s, e in _children(data, start, end):                # RDN SET
        for _, as_, ae in _children(data, s, e):                 # AttributeTypeAndValue
            kids = _children(data, as_, ae)
            if len(kids) != 2 or kids[0][0] != 0x06:
                continue
            attr = _NAME_ATTRS.get(_oid(data[kids[0][1]:kids[0][2]]))
            if not attr or attr in found:
                continue
            vtag, vs, ve = kids[1]
            raw = data[vs:ve]
            text = raw.decode("utf-16-be" if vtag == 0x1E else "utf-8", "replace")
            found[attr] = "".join(ch for ch in text if ch.isprintable())[:80]
    for attr in ("CN", "O", "OU"):
        if attr in found:
            return "%s=%s" % (attr, found[attr])
    return ""


def _algorithm_identifier(data: bytes, start: int, end: int) -> Tuple[str, str]:
    """Return (algorithm OID, parameter OID or '')."""
    kids = _children(data, start, end)
    if not kids or kids[0][0] != 0x06:
        raise DerError("no algorithm OID")
    alg = _oid(data[kids[0][1]:kids[0][2]])
    param = ""
    if len(kids) > 1 and kids[1][0] == 0x06:
        param = _oid(data[kids[1][1]:kids[1][2]])
    return alg, param


def _spki(data: bytes, start: int, end: int) -> Tuple[str, Optional[int], str]:
    """Parse SubjectPublicKeyInfo. Return (rule id, bits, display name)."""
    kids = _children(data, start, end)
    if len(kids) < 2 or kids[0][0] != 0x30 or kids[1][0] != 0x03:
        raise DerError("not a SubjectPublicKeyInfo")
    alg_oid, param = _algorithm_identifier(data, kids[0][1], kids[0][2])
    name = OID_NAMES.get(alg_oid)
    if name is None:
        raise DerError("unknown key algorithm " + alg_oid)
    return _describe_key(name, param, data[kids[1][1] + 1:kids[1][2]])


def _describe_key(name: str, param_oid: str, key_bytes: bytes):
    rule_id = KEY_RULES[name]
    if name in ("rsaEncryption", "RSASSA-PSS"):
        bits = None
        try:
            tag, s, e = _tlv(key_bytes, 0)
            inner = _children(key_bytes, s, e)
            if tag == 0x30 and inner and inner[0][0] == 0x02:
                bits = _uint_bits(key_bytes[inner[0][1]:inner[0][2]])
        except DerError:
            pass
        return rule_id, bits, "RSA"
    if name == "id-ecPublicKey":
        curve, bits = CURVES.get(param_oid, ("unknown curve", None))
        return rule_id, bits, "EC " + curve
    if name == "DSA":
        return rule_id, None, "DSA"
    if name in ("dhKeyAgreement", "dhpublicnumber"):
        return rule_id, None, "Diffie-Hellman"
    return rule_id, None, name


def parse_certificate(der: bytes) -> CryptoObject:
    tag, s, e = _tlv(der, 0)
    if tag != 0x30:
        raise DerError("not a SEQUENCE")
    top = _children(der, s, e)
    if len(top) < 3 or top[0][0] != 0x30 or top[1][0] != 0x30:
        raise DerError("not a Certificate")
    tbs = _children(der, top[0][1], top[0][2])
    if tbs and tbs[0][0] == 0xA0:      # explicit version
        tbs = tbs[1:]
    if len(tbs) < 6:
        raise DerError("short TBSCertificate")
    _serial, _sig, issuer, validity, subject, spki = tbs[:6]
    if spki[0] != 0x30 or validity[0] != 0x30:
        raise DerError("unexpected TBSCertificate layout")

    sig_oid, _ = _algorithm_identifier(der, top[1][1], top[1][2])
    sig_name = OID_NAMES.get(sig_oid, sig_oid)
    rule_id, bits, key_name = _spki(der, spki[1], spki[2])

    times = _children(der, validity[1], validity[2])
    not_before = _time(times[0][0], der[times[0][1]:times[0][2]]) if times else ""
    not_after = _time(times[1][0], der[times[1][1]:times[1][2]]) if len(times) > 1 else ""

    lower = sig_name.lower()
    weak = "SHA-1" if "sha1" in lower else ("MD5" if "md5" in lower else "")

    return CryptoObject(
        line=0, kind="certificate", rule_id=rule_id, key_algorithm=key_name,
        key_bits=bits, signature_algorithm=sig_name, weak_signature_hash=weak,
        subject=_name(der, subject[1], subject[2]),
        issuer=_name(der, issuer[1], issuer[2]),
        not_before=not_before, not_after=not_after,
        self_signed=der[issuer[1]:issuer[2]] == der[subject[1]:subject[2]],
    )


def _parse_public_key(der: bytes) -> CryptoObject:
    tag, s, e = _tlv(der, 0)
    rule_id, bits, name = _spki(der, s, e)
    return CryptoObject(0, "public-key", rule_id, name, bits)


def _parse_pkcs8(der: bytes) -> CryptoObject:
    tag, s, e = _tlv(der, 0)
    kids = _children(der, s, e)
    if len(kids) < 3 or kids[0][0] != 0x02 or kids[1][0] != 0x30:
        raise DerError("not PKCS#8")
    alg_oid, param = _algorithm_identifier(der, kids[1][1], kids[1][2])
    name = OID_NAMES.get(alg_oid)
    if name is None:
        raise DerError("unknown key algorithm " + alg_oid)
    rule_id, bits, display = _describe_key(name, param, b"")
    if name in ("rsaEncryption", "RSASSA-PSS") and kids[2][0] == 0x04:
        inner = der[kids[2][1]:kids[2][2]]          # RSAPrivateKey
        try:
            bits = _pkcs1_bits(inner)
        except DerError:
            bits = None
    return CryptoObject(0, "private-key", rule_id, display, bits)


def _pkcs1_bits(der: bytes) -> Optional[int]:
    tag, s, e = _tlv(der, 0)
    kids = _children(der, s, e)
    if len(kids) < 2 or kids[0][0] != 0x02 or kids[1][0] != 0x02:
        raise DerError("not an RSA key")
    # RSAPrivateKey starts with a version INTEGER; RSAPublicKey starts with n
    first = der[kids[0][1]:kids[0][2]]
    if len(kids) >= 9 or len(first) <= 1:
        return _uint_bits(der[kids[1][1]:kids[1][2]])
    return _uint_bits(first)


def _parse_sec1(der: bytes) -> CryptoObject:
    tag, s, e = _tlv(der, 0)
    curve, bits = "unknown curve", None
    for ktag, ks, ke in _children(der, s, e):
        if ktag == 0xA0:                             # [0] ECParameters
            inner = _children(der, ks, ke)
            if inner and inner[0][0] == 0x06:
                curve, bits = CURVES.get(_oid(der[inner[0][1]:inner[0][2]]),
                                         ("unknown curve", None))
    return CryptoObject(0, "private-key", "ECDSA-001", "EC " + curve, bits)


def _ssh_string(blob: bytes, pos: int) -> Tuple[bytes, int]:
    if pos + 4 > len(blob):
        raise DerError("truncated ssh blob")
    n = int.from_bytes(blob[pos:pos + 4], "big")
    if pos + 4 + n > len(blob):
        raise DerError("truncated ssh blob")
    return blob[pos + 4:pos + 4 + n], pos + 4 + n


def _ssh_key(key_type: str, blob: bytes, kind: str) -> CryptoObject:
    if key_type.startswith("ecdsa-sha2-nistp"):
        bits = int(key_type[len("ecdsa-sha2-nistp"):])
        return CryptoObject(0, kind, "ECDSA-001", "EC P-%d" % bits, bits)
    rule_id = SSH_RULES.get(key_type)
    if rule_id is None:
        raise DerError("unknown ssh key type")
    bits = None
    name = {"ssh-rsa": "RSA", "ssh-dss": "DSA", "ssh-ed25519": "Ed25519"}[key_type]
    try:
        declared, pos = _ssh_string(blob, 0)
        if key_type == "ssh-rsa" and declared == b"ssh-rsa":
            _e, pos = _ssh_string(blob, pos)
            n, pos = _ssh_string(blob, pos)
            bits = _uint_bits(n)
        elif key_type == "ssh-dss" and declared == b"ssh-dss":
            p, pos = _ssh_string(blob, pos)
            bits = _uint_bits(p)
    except DerError:
        pass
    return CryptoObject(0, kind, rule_id, name, bits)


def _parse_openssh_private(raw: bytes) -> CryptoObject:
    magic = b"openssh-key-v1\x00"
    if not raw.startswith(magic):
        raise DerError("not an OpenSSH key")
    pos = len(magic)
    _cipher, pos = _ssh_string(raw, pos)
    _kdf, pos = _ssh_string(raw, pos)
    _kdfopts, pos = _ssh_string(raw, pos)
    pos += 4                                         # number of keys
    pub, pos = _ssh_string(raw, pos)
    key_type, _ = _ssh_string(pub, 0)
    return _ssh_key(key_type.decode("ascii", "replace"), pub, "private-key")


def _b64(body: str) -> bytes:
    # PEM bodies may carry RFC 1421 headers ("Proc-Type: 4,ENCRYPTED")
    lines = [ln.strip() for ln in body.splitlines()]
    lines = [ln for ln in lines if ln and ":" not in ln]
    try:
        return base64.b64decode("".join(lines), validate=False)
    except (binascii.Error, ValueError) as exc:
        raise DerError(str(exc))


def _from_pem(label: str, body: str) -> Optional[CryptoObject]:
    if "ENCRYPTED" in label or "Proc-Type: 4,ENCRYPTED" in body:
        rule = {"RSA PRIVATE KEY": "RSA-001", "EC PRIVATE KEY": "ECDSA-001",
                "DSA PRIVATE KEY": "DSA-001"}.get(label)
        if rule is None:
            return None        # algorithm is inside the ciphertext
        name = label.split()[0]
        return CryptoObject(0, "private-key", rule, name, encrypted=False)
    der = _b64(body)
    if label in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
        return parse_certificate(der)
    if label == "PUBLIC KEY":
        return _parse_public_key(der)
    if label == "PRIVATE KEY":
        return _parse_pkcs8(der)
    if label == "RSA PRIVATE KEY":
        return CryptoObject(0, "private-key", "RSA-001", "RSA", _pkcs1_bits(der))
    if label == "RSA PUBLIC KEY":
        return CryptoObject(0, "public-key", "RSA-001", "RSA", _pkcs1_bits(der))
    if label == "EC PRIVATE KEY":
        return _parse_sec1(der)
    if label == "DSA PRIVATE KEY":
        return CryptoObject(0, "private-key", "DSA-001", "DSA")
    if label == "OPENSSH PRIVATE KEY":
        return _parse_openssh_private(der)
    return None


def scan_text(text: str) -> List[CryptoObject]:
    """Find and parse every PEM block and OpenSSH public key in `text`."""
    found: List[CryptoObject] = []
    if "-----BEGIN " in text:
        for m in PEM_RE.finditer(text):
            try:
                obj = _from_pem(m.group(1), m.group(2))
            except (DerError, IndexError):
                obj = None
            if obj is not None:
                obj.line = text.count("\n", 0, m.start()) + 1
                found.append(obj)
    if "AAAA" in text:
        for m in SSH_PUB_RE.finditer(text):
            try:
                blob = base64.b64decode(m.group(2) + "=" * (-len(m.group(2)) % 4))
                obj = _ssh_key(m.group(1), blob, "ssh-public-key")
            except (DerError, binascii.Error, ValueError):
                continue
            obj.line = text.count("\n", 0, m.start()) + 1
            found.append(obj)
    return found


def scan_der(data: bytes) -> Optional[CryptoObject]:
    """Parse a binary DER certificate file."""
    try:
        obj = parse_certificate(data)
    except (DerError, IndexError):
        return None
    obj.line = 1
    return obj


def years_left(not_after: str, today: Optional[datetime.date] = None) -> Optional[float]:
    try:
        end = datetime.date.fromisoformat(not_after)
    except ValueError:
        return None
    today = today or datetime.date.today()
    return (end - today).days / 365.25
