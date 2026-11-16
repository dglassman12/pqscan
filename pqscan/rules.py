"""
Detection rules for cryptographic algorithms and their post-quantum status.

Each rule names one algorithm and carries two sets of regular expressions:

    strong   unambiguous on their own ("RSA-2048", "ecdsa", "ssh-rsa")
    weak     short tokens that are only crypto in a crypto context ("rsa",
             "DES", "P-256"). A weak match is kept only if the same file
             contains a strong match or a general crypto keyword.

Patterns are run over the whole file text at once, so they must never match
across a newline: use [ \\t] rather than \\s.

Word boundaries are deliberately NOT \\b. In real code the separators around
an algorithm name are underscores, hyphens and camelCase humps
(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, SHA256withRSA, ML_KEM_768), and \\b
treats "_" as a word character. NB / NE below mean "not preceded / followed
by a letter or digit".

When two matches overlap on a line, the longer one wins. That is what keeps
"ML-DSA" from being reported as "DSA", "3DES" as "DES", and "X25519MLKEM768"
as plain X25519.

Risk levels (default "nist" policy):
    critical  public-key algorithm broken by Shor's algorithm
    high      classically weak; replace regardless of quantum
    medium    weak-ish legacy primitive
    low       approved today, but below the strictest profiles
    info      inventory item that needs a human to confirm a parameter
    safe      post-quantum safe
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

NB = r"(?<![A-Za-z0-9])"
NE = r"(?![A-Za-z0-9])"


def I(pattern: str) -> str:
    """Case-insensitive group that can sit inside a larger alternation."""
    return "(?i:" + pattern + ")"


@dataclass(frozen=True)
class Rule:
    id: str
    algorithm: str
    family: str        # signature | key-agreement | pke | kem | block-cipher |
                       # stream-cipher | hash | protocol | ec
    quantum: str       # shor | grover | classic | safe
    risk: str
    use: str           # key-establishment | signature | general | symmetric |
                       # hash | protocol
    replace_with: str
    hints: Tuple[str, ...]            # lowercase substrings; cheap prefilter
    strong: Optional["re.Pattern"]
    weak: Optional["re.Pattern"]
    note: str = ""
    yields_to: Tuple[str, ...] = ()   # drop this finding if one of these
                                      # algorithms is found on the same line
    yields_generic_to: Tuple[str, ...] = ()   # the same, but only when the
                                      # match names no parameter (no digits)


def _compile(patterns) -> Optional["re.Pattern"]:
    if not patterns:
        return None
    return re.compile("|".join("(?:" + p + ")" for p in patterns))


def _rule(id, algorithm, family, quantum, risk, use, replace_with, hints,
          strong=(), weak=(), note="", yields_to=(), yields_generic_to=()) -> Rule:
    return Rule(
        id=id, algorithm=algorithm, family=family, quantum=quantum, risk=risk,
        use=use, replace_with=replace_with, hints=tuple(hints),
        strong=_compile(strong), weak=_compile(weak), note=note,
        yields_to=tuple(yields_to), yields_generic_to=tuple(yields_generic_to),
    )


_KEM = "ML-KEM (FIPS 203); a hybrid such as X25519MLKEM768 during transition"
_SIG = "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)"
_BOTH = ("ML-KEM (FIPS 203) for key establishment and encryption; "
         "ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures")
_HASH = "SHA-256 or stronger (SHA-384 for CNSA 2.0)"
_SYM = "AES-256 (GCM) or ChaCha20-Poly1305"

RULES = [
    # ------------------------------------------------------------------
    # Public-key algorithms broken by Shor's algorithm
    # ------------------------------------------------------------------
    _rule(
        "RSA-001", "RSA", "pke", "shor", "critical", "general", _BOTH,
        hints=("rsa", "pkcs", "oaep"),
        strong=[
            I(NB + r"rsa[-_ ]?(?:1024|2048|3072|4096|7680|8192|15360)(?![0-9])"),
            I(r"BEGIN RSA (?:PRIVATE|PUBLIC) KEY"),
            I(r"rsaEncryption"),
            I(r"genrsa"),
            I(NB + r"rsa[-_]?oaep"),
            I(NB + r"oaep"),
            I(r"pkcs[#_ ]?1(?![0-9])"),
            r"(?<![A-Z0-9])RSA(?![a-z])",
            r"(?<![A-Z])Rsa(?![a-z])",
            # rsa.GenerateKey(...), rsa.generate_private_key(...). Not any
            # method on a variable called rsa: in Go networking code that is
            # a raw socket address (rsa.Sockaddr()).
            NB + r"rsa\.(?:GenerateKey|GenerateMultiPrimeKey|(?:En|De)crypt(?:OAEP|PKCS1v15)\w*|"
                 r"(?:Sign|Verify)(?:PKCS1v15|PSS)|PublicKey|PrivateKey|generate_private_key|"
                 r"newkeys|import_?[kK]ey|encrypt|decrypt|sign|verify)(?![A-Za-z0-9_])",
        ],
        weak=[NB + r"rsa" + NE],
    ),
    _rule(
        "RSA-002", "RSA", "signature", "shor", "critical", "signature", _SIG,
        hints=("rs256", "rs384", "rs512", "ps256", "ps384", "ps512",
               "withrsa", "with_rsa", "rsa-sha", "rsa_sha", "ssh-rsa",
               "rsassa", "rsa-pss", "rsa_pss"),
        strong=[
            NB + r"(?:RS|PS)(?:256|384|512)" + NE,
            I(r"with_?rsa(?:encryption)?"),
            I(NB + r"rsa(?=[-_]sha)"),
            I(r"ssh-rsa"),
            I(r"rsassa(?:[-_]?pss)?"),
            I(NB + r"rsa[-_]pss"),
        ],
    ),
    _rule(
        "ECDSA-001", "ECDSA", "signature", "shor", "critical", "signature", _SIG,
        hints=("ecdsa", "es256", "es384", "es512"),
        strong=[
            I(r"ecdsa"),
            NB + r"ES(?:256K?|384|512)" + NE,
        ],
    ),
    _rule(
        "ECDH-001", "ECDH", "key-agreement", "shor", "critical",
        "key-establishment", _KEM,
        hints=("ecdh",),
        # "ssl_ecdh_curve" / "ECDHCurve" name a setting, not a use; the
        # curve or group that follows is matched by its own rule
        strong=[I(r"ecdhe?(?![-_]?curve)")],
    ),
    _rule(
        "ECDH-002", "X25519 / X448", "key-agreement", "shor", "critical",
        "key-establishment", _KEM,
        hints=("25519", "x448", "curve448"),
        strong=[
            I(NB + r"(?:x25519|curve25519|curve448)"),
            NB + r"X448",                       # lowercase x448 is a variable name
            r"(?<=[\"'])x448(?=[\"'])",
        ],
    ),
    _rule(
        "EDDSA-001", "EdDSA", "signature", "shor", "critical", "signature", _SIG,
        hints=("eddsa", "ed25519", "ed448"),
        strong=[
            I(r"eddsa"),
            I(NB + r"ed25519"),
            I(NB + r"ed448"),
        ],
    ),
    _rule(
        "ECC-001", "Elliptic curve (scheme not stated)", "ec", "shor",
        "critical", "general",
        "ML-KEM (FIPS 203) for key agreement; ML-DSA (FIPS 204) for signatures",
        hints=("sec", "prime", "nistp", "brainpool", "begin ec", "\"ec\"",
               "'ec'", "ec.", "elliptic", "evp_pkey_ec", "ecparam", "ecpublickey",
               "p-256", "p256", "p-384", "p384", "p-521", "p521"),
        strong=[
            I(r"sec[pt](?:160|192|224|256|384|521)[rk][12]"),
            I(r"prime(?:192|256)v1"),
            I(r"nistp-?(?:256|384|521)"),
            I(r"brainpoolp(?:256|384|512)[rt]1"),
            I(r"BEGIN EC (?:PRIVATE KEY|PARAMETERS)"),
            I(r"getInstance\([ \t]*[\"']EC[\"']"),
            NB + r"ec\.(?:generate_private_key|derive_private_key|EllipticCurve\w*)",
            r"elliptic\.P(?:224|256|384|521)",
            r"EVP_PKEY_EC" + NE,
            I(NB + r"ecparam"),
            I(r"id-ecPublicKey"),
            I(r"elliptic[ _-]curve"),
        ],
        weak=[NB + r"P-?(?:256|384|521)" + NE],
        yields_to=("ECDSA", "ECDH"),
        yields_generic_to=("EdDSA", "X25519 / X448"),
    ),
    _rule(
        "DH-001", "Diffie-Hellman (finite field)", "key-agreement", "shor",
        "critical", "key-establishment", _KEM,
        hints=("dh", "diffie", "modp"),
        strong=[
            I(r"diffie[-_ ]?hellman"),
            NB + r"DHE(?=[-_])",
            I(r"dhparam"),
            I(r"ffdhe(?:2048|3072|4096|6144|8192)"),
            I(NB + r"modp[-_]?(?:768|1024|1536|2048|3072|4096|6144|8192)"),
            NB + r"DH_(?:generate|compute|new|check|size|bits|get0|set0)\w*",
            r"(?<![A-Za-z])DH(?:ParameterSpec|PublicKey|PrivateKey|GenParameterSpec)",
            I(r"getInstance\([ \t]*[\"'](?:DH|DiffieHellman)[\"']"),
            NB + r"dh\.(?:generate_parameters|DHParameterNumbers|DHPublicNumbers)",
            r"dhKeyAgreement",
        ],
        weak=[r"(?<![A-Za-z0-9_])DH(?![A-Za-z0-9_])"],
    ),
    _rule(
        "DSA-001", "DSA", "signature", "shor", "critical", "signature", _SIG,
        hints=("dsa", "ssh-dss"),
        strong=[
            I(r"ssh-dss"),
            I(r"with_?dsa"),
            I(r"BEGIN DSA (?:PRIVATE KEY|PARAMETERS)"),
            I(NB + r"dsaparam"),
            I(NB + r"gendsa"),
            NB + r"DSA_(?:generate|sign|verify|new|do_sign|do_verify|size)\w*",
            NB + r"DSA(?:PublicKey|PrivateKey|ParameterSpec|KeyPairGenerator|Signer|Params)",
            I(r"getInstance\([ \t]*[\"']DSA[\"']"),
            r"EVP_PKEY_DSA" + NE,
            I(NB + r"dsa(?=[-_]sha)"),
        ],
        weak=[NB + r"(?:DSA|dsa|Dsa)" + NE],
    ),
    _rule(
        "ELGAMAL-001", "ElGamal", "pke", "shor", "critical",
        "key-establishment", _KEM,
        hints=("gamal",),
        strong=[I(r"el-?gamal")],
    ),

    # ------------------------------------------------------------------
    # Post-quantum and hybrid algorithms. Recorded so the inventory shows
    # migration progress, not just debt.
    # ------------------------------------------------------------------
    _rule(
        "HYBRID-001", "Hybrid PQ key exchange", "kem", "safe", "safe",
        "key-establishment", "",
        hints=("mlkem", "ml-kem", "kyber", "sntrup", "wing"),
        strong=[
            I(r"x25519[-_]?(?:ml-?kem|kyber)[-_]?(?:512|768|1024)?(?:[-_]?draft\d+)?"),
            I(r"(?:secp|p-?)(?:256|384|521)(?:r1)?[-_]?(?:ml-?kem|kyber)[-_]?(?:768|1024)?"),
            I(r"(?:ml-?kem|kyber)[-_]?(?:512|768|1024)?[-_]?(?:x25519|p-?256|p-?384)(?:-sha(?:256|384|512))?"),
            I(r"sntrup761[-_]?x25519(?:-sha512)?"),
        ],
        weak=[I(NB + r"x-?wing" + NE)],
        note="Classical + post-quantum combined; secure if either holds.",
    ),
    _rule(
        "MLKEM-001", "ML-KEM", "kem", "safe", "safe", "key-establishment", "",
        hints=("mlkem", "ml-kem", "ml_kem", "kyber"),
        strong=[
            I(NB + r"ml[-_]?kem(?:[-_]?(?:512|768|1024))?"),
            I(r"(?:crystals[-_])?kyber(?:[-_]?(?:512|768|1024))?") + r"(?![a-z])",
        ],
        note="FIPS 203.",
    ),
    _rule(
        "MLDSA-001", "ML-DSA", "signature", "safe", "safe", "signature", "",
        hints=("mldsa", "ml-dsa", "ml_dsa", "dilithium"),
        strong=[
            I(NB + r"ml[-_]?dsa(?:[-_]?(?:44|65|87))?"),
            I(r"(?:crystals[-_])?dilithium(?:[-_]?[235])?"),
        ],
        note="FIPS 204.",
    ),
    _rule(
        "SLHDSA-001", "SLH-DSA", "signature", "safe", "safe", "signature", "",
        hints=("slh", "sphincs"),
        strong=[
            I(NB + r"slh[-_]?dsa(?:[-_](?:sha2|shake)[-_]?(?:128|192|256)[sf])?"),
            I(r"sphincs\+?"),
        ],
        note="FIPS 205.",
    ),
    _rule(
        "FNDSA-001", "FN-DSA (Falcon)", "signature", "safe", "safe",
        "signature", "",
        hints=("fn-dsa", "fndsa", "fn_dsa", "falcon"),
        strong=[
            I(NB + r"fn[-_]?dsa(?:[-_]?(?:512|1024))?"),
            I(NB + r"falcon[-_]?(?:512|1024)"),
        ],
        note="FIPS 206 was still a draft when this rule set was written; "
             "treat as pre-standard.",
    ),
    _rule(
        "HQC-001", "HQC", "kem", "safe", "safe", "key-establishment", "",
        hints=("hqc",),
        strong=[I(NB + r"hqc[-_]?(?:128|192|256)")],
        weak=[NB + r"HQC" + NE],
        note="Selected by NIST as a backup KEM; standard not yet final.",
    ),
    _rule(
        "LMS-001", "LMS / XMSS", "signature", "safe", "safe", "signature", "",
        hints=("xmss", "lms", "lmots"),
        strong=[
            I(NB + r"xmss(?:\^?mt)?"),
            I(r"hss[-_/]lms"),
            I(NB + r"lms[-_]sha256\w*"),
            r"LMOTS",
        ],
        note="Stateful hash-based signatures (NIST SP 800-208).",
    ),
    _rule(
        "PQC-001", "Other PQC KEM", "kem", "safe", "safe",
        "key-establishment", "",
        hints=("mceliece", "frodo", "ntru", "bike-l", "bikel"),
        strong=[
            I(r"mceliece\d*"),
            I(r"frodo-?kem"),
            I(NB + r"sntrup\d+"),
            I(NB + r"ntru[-_]?(?:hps|hrss|prime)\w*"),
            I(NB + r"bike-?l[135]"),
        ],
        note="Post-quantum by design but not a NIST standard.",
    ),

    # ------------------------------------------------------------------
    # Symmetric ciphers
    # ------------------------------------------------------------------
    _rule(
        "AES-128", "AES-128", "block-cipher", "grover", "low", "symmetric",
        "AES-256 where policy requires it",
        hints=("aes",),
        strong=[I(NB + r"aes[-_ ]?128(?![0-9])")],
        note="Grover's algorithm weakens but does not break AES-128; NIST "
             "still approves it. CNSA 2.0 requires AES-256.",
    ),
    _rule(
        "AES-192", "AES-192", "block-cipher", "grover", "low", "symmetric",
        "AES-256 where policy requires it",
        hints=("aes",),
        strong=[I(NB + r"aes[-_ ]?192(?![0-9])")],
        note="Approved by NIST. CNSA 2.0 requires AES-256.",
    ),
    _rule(
        "AES-256", "AES-256", "block-cipher", "safe", "safe", "symmetric", "",
        hints=("aes",),
        strong=[I(NB + r"aes[-_ ]?256(?![0-9])")],
    ),
    _rule(
        "AES-000", "AES (key size not stated)", "block-cipher", "grover",
        "info", "symmetric", "Confirm the key length; use 256-bit keys",
        hints=("aes",),
        strong=[
            r"(?<![A-Za-z0-9])AES(?![a-z0-9])",
            r"(?<![A-Za-z])Aes(?![a-z])",
        ],
        weak=[NB + r"aes" + NE],
        note="The key length is set at runtime and cannot be read statically.",
        yields_to=("AES-128", "AES-192", "AES-256"),
    ),
    _rule(
        "3DES-001", "3DES", "block-cipher", "classic", "high", "symmetric",
        _SYM,
        hints=("des", "tdea"),
        strong=[
            I(NB + r"(?:3des|triple[-_ ]?des|desede|des[-_]?ede3?|des3|tdea|tdes)"),
        ],
        note="64-bit block (Sweet32) and 112-bit strength.",
    ),
    _rule(
        "DES-001", "DES", "block-cipher", "classic", "high", "symmetric", _SYM,
        hints=("des",),
        strong=[
            I(NB + r"des[-_](?:cbc|ecb|cfb|ofb)"),
            NB + r"des\.(?:new|MODE_\w+|NewCipher)",
            NB + r"DES_(?:ecb|cbc|ncbc|set_key|encrypt|crypt)\w*",
            I(r"getInstance\([ \t]*[\"']DES(?:/[^\"'\n]*)?[\"']"),
        ],
        weak=[NB + r"DES" + NE],
        note="56-bit key; broken by brute force since the 1990s.",
    ),
    _rule(
        "RC4-001", "RC4", "stream-cipher", "classic", "high", "symmetric", _SYM,
        hints=("rc4", "arcfour", "arc4"),
        strong=[I(NB + r"(?:rc4|arcfour|arc4)(?!random)(?![0-9])")],
        note="Biased keystream; prohibited in TLS (RFC 7465).",
    ),
    _rule(
        "BLOWFISH-001", "Blowfish", "block-cipher", "classic", "medium",
        "symmetric", _SYM,
        hints=("blowfish", "bf-"),
        strong=[I(r"blowfish"), NB + r"BF-(?:CBC|ECB|CFB|OFB)"],
        note="64-bit block (Sweet32).",
    ),
    _rule(
        "CHACHA-001", "ChaCha20", "stream-cipher", "safe", "safe",
        "symmetric", "",
        hints=("chacha",),
        strong=[I(r"x?chacha20(?:[-_]?poly1305)?")],
    ),

    # ------------------------------------------------------------------
    # Hash functions
    # ------------------------------------------------------------------
    _rule(
        "MD5-001", "MD5", "hash", "classic", "high", "hash", _HASH,
        hints=("md5",),
        # mixed case such as "mD5" only turns up inside encoded data
        strong=[
            NB + r"md5(?![0-9])",
            r"MD5(?![0-9])",
            r"(?<![A-Z0-9])Md5(?![0-9])",
        ],
        note="Practical collisions since 2004.",
    ),
    _rule(
        "MD4-001", "MD4", "hash", "classic", "high", "hash", _HASH,
        hints=("md4",),
        strong=[I(NB + r"md4(?![0-9])")],
    ),
    _rule(
        "SHA1-001", "SHA-1", "hash", "classic", "high", "hash", _HASH,
        hints=("sha",),
        strong=[
            I(r"sha[-_]?1(?![0-9])"),
            # TLS suite names end in a bare SHA to mean HMAC-SHA1:
            # TLS_RSA_WITH_AES_128_CBC_SHA, AES128-SHA, DES-CBC3-SHA
            r"(?:(?<=CBC[-_])|(?<=CBC3[-_])|(?<=RC4[-_])|(?<=128[-_])|(?<=256[-_]))"
            r"SHA(?![-_]?[A-Za-z0-9])",
        ],
        note="Practical collisions since 2017.",
    ),
    _rule(
        "SHA256-001", "SHA-256", "hash", "safe", "safe", "hash", "",
        hints=("sha",),
        strong=[I(r"sha[-_]?256(?![0-9])"), I(r"sha2[-_]256")],
        note="Approved by NIST. CNSA 2.0 requires SHA-384 or SHA-512.",
    ),
    _rule(
        "SHA384-001", "SHA-384", "hash", "safe", "safe", "hash", "",
        hints=("sha",),
        strong=[I(r"sha[-_]?384(?![0-9])"), I(r"sha2[-_]384")],
    ),
    _rule(
        "SHA512-001", "SHA-512", "hash", "safe", "safe", "hash", "",
        hints=("sha",),
        strong=[I(r"sha[-_]?512(?![0-9/])"), I(r"sha2[-_]512")],
    ),
    _rule(
        "SHA3-001", "SHA-3", "hash", "safe", "safe", "hash", "",
        hints=("sha3", "shake", "keccak"),
        strong=[
            I(r"sha3[-_]?(?:224|256|384|512)"),
            I(NB + r"shake[-_]?(?:128|256)"),
            I(r"keccak(?:[-_]?(?:224|256|384|512))?"),
        ],
    ),

    # ------------------------------------------------------------------
    # Protocol versions that cannot carry post-quantum key exchange
    # ------------------------------------------------------------------
    _rule(
        "TLS-001", "TLS 1.0 / 1.1", "protocol", "classic", "high", "protocol",
        "TLS 1.3 (the only version with post-quantum hybrid key exchange)",
        hints=("tls",),
        strong=[
            I(NB + r"tlsv?1[._][01](?![0-9])"),
            I(NB + r"tlsv1(?![._0-9])"),
            I(NB + r"tls 1\.[01](?![0-9])"),
            r"VersionTLS1[01]",
            r"TLS1_(?:1_)?VERSION",
        ],
        note="Deprecated by RFC 8996.",
    ),
    _rule(
        "SSL-001", "SSL 2.0 / 3.0", "protocol", "classic", "high", "protocol",
        "TLS 1.3 (the only version with post-quantum hybrid key exchange)",
        hints=("ssl",),
        strong=[
            I(NB + r"sslv[23](?![0-9])"),          # SSLv23 means "negotiate"
            I(NB + r"ssl ?[23]\.0"),
            r"VersionSSL30",
        ],
        note="Broken (POODLE); prohibited by RFC 7568.",
    ),
]

RULES_BY_ID: Dict[str, Rule] = {r.id: r for r in RULES}

RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "safe": 5}
RISK_LEVELS = ("critical", "high", "medium", "low", "info", "safe")

RISK_LABELS = {
    "critical": "Quantum-vulnerable public-key crypto",
    "high": "Classically weak, replace regardless",
    "medium": "Legacy or below policy",
    "low": "Approved, below strictest profile",
    "info": "Needs a human to confirm",
    "safe": "Post-quantum safe",
}

# Migration priority. The order follows the threat, not the count:
#   1  key establishment and public-key encryption: traffic recorded today can
#      be decrypted once a quantum computer exists ("harvest now, decrypt later")
#   2  signatures and certificates: forgery needs a quantum computer at the
#      time of the attack, so there is more runway
#   3  classically weak primitives: broken already, cheap to fix
#   4  policy and hardening items
PRIORITY_LABELS = {
    1: ("Key establishment and encryption",
        "Exposed to harvest-now-decrypt-later: traffic captured today can be "
        "decrypted later. Move these first, starting with anything that "
        "protects data with a long confidentiality lifetime."),
    2: ("Signatures and certificates",
        "Forgery needs a quantum computer at attack time, so there is more "
        "runway. Start with long-lived roots of trust: code signing, firmware, "
        "CA certificates."),
    3: ("Classically weak primitives",
        "Already broken or deprecated without any quantum computer. Usually "
        "the cheapest fixes on the list."),
    4: ("Policy and hardening",
        "Approved today but below the selected policy, or a parameter that "
        "needs a human to confirm."),
}


def priority_for(quantum: str, use: str, risk: str) -> int:
    if risk == "safe":
        return 0
    if quantum == "shor":
        return 2 if use == "signature" else 1
    if risk in ("critical", "high"):
        return 3
    return 4


# ----------------------------------------------------------------------
# Policies
# ----------------------------------------------------------------------

POLICIES = {
    "nist": "FIPS 203/204/205 and NIST IR 8547",
    "cnsa2": "NSA CNSA 2.0 (AES-256, SHA-384/512, ML-KEM-1024, ML-DSA-87 only)",
}

_PARAM = re.compile(r"(\d{2,4})")


def apply_policy(policy: str, algorithm: str, match: str, risk: str, note: str):
    """Return (risk, note) adjusted for the selected policy."""
    if policy != "cnsa2":
        return risk, note

    if algorithm in ("AES-128", "AES-192"):
        return "high", "CNSA 2.0 requires AES-256."
    if algorithm == "SHA-256":
        return "medium", "CNSA 2.0 requires SHA-384 or SHA-512."
    if algorithm == "ChaCha20":
        return "medium", "Not part of CNSA 2.0, which specifies AES-256."
    if algorithm == "ML-KEM":
        m = _PARAM.search(match)
        if m and m.group(1) in ("512", "768"):
            return "medium", "CNSA 2.0 requires ML-KEM-1024."
        if not m:
            return "info", "Confirm the parameter set; CNSA 2.0 requires ML-KEM-1024."
    if algorithm == "ML-DSA":
        m = _PARAM.search(match)
        if m and m.group(1) in ("44", "65"):
            return "medium", "CNSA 2.0 requires ML-DSA-87."
        if not m:
            return "info", "Confirm the parameter set; CNSA 2.0 requires ML-DSA-87."
    if algorithm in ("SLH-DSA", "FN-DSA (Falcon)", "HQC", "Other PQC KEM"):
        return "medium", "Not part of CNSA 2.0."
    return risk, note
