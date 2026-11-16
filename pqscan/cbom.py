"""
CycloneDX 1.6 cryptography bill of materials (CBOM).

One component per algorithm, with every place it was found recorded as an
evidence occurrence. Certificates, protocol versions and crypto libraries get
their own components. The output validates against the official CycloneDX 1.6
JSON schema (see tests/test_outputs.py).

See https://cyclonedx.org/capabilities/cbom/
"""

from __future__ import annotations

import datetime
import os
import re
import uuid
from typing import Dict, List

from . import __version__
from .scanner import Finding, ScanResult

_SLUG = re.compile(r"[^a-z0-9]+")

# family -> (primitive, cryptoFunctions)
_FAMILY = {
    "signature": ("signature", ["sign", "verify"]),
    "key-agreement": ("key-agree", ["keygen", "keyderive"]),
    "pke": ("pke", ["keygen", "encrypt", "decrypt", "sign", "verify"]),
    "kem": ("kem", ["keygen", "encapsulate", "decapsulate"]),
    "block-cipher": ("block-cipher", ["encrypt", "decrypt"]),
    "stream-cipher": ("stream-cipher", ["encrypt", "decrypt"]),
    "hash": ("hash", ["digest"]),
    "ec": ("other", ["keygen"]),
}

# NIST post-quantum security category, where one is defined
_LEVELS = {
    "AES-128": 1, "AES-192": 3, "AES-256": 5,
    "SHA-256": 2, "SHA-384": 4, "SHA-512": 5,
}
_PARAM_LEVELS = {
    "ML-KEM": {"512": 1, "768": 3, "1024": 5},
    "ML-DSA": {"44": 2, "65": 3, "87": 5},
}
_ECOSYSTEM_PURL = {"pypi": "pypi", "npm": "npm", "maven": None, "go": "golang",
                   "rubygems": "gem", "composer": "composer", "cargo": "cargo"}


def _slug(text: str) -> str:
    return _SLUG.sub("-", text.lower()).strip("-")


def _parameter_set(algorithm: str, findings: List[Finding]) -> str:
    """The parameter set, if every occurrence agrees on one."""
    table = _PARAM_LEVELS.get(algorithm)
    if not table:
        return ""
    seen = set()
    for f in findings:
        m = re.search(r"(\d{2,4})", f.match + " " + f.detail)
        seen.add(m.group(1) if m and m.group(1) in table else "")
    return seen.pop() if len(seen) == 1 else ""


def _algorithm_component(algorithm: str, findings: List[Finding]) -> dict:
    first = findings[0]
    primitive, functions = _FAMILY.get(first.family, ("unknown", ["unknown"]))
    if algorithm == "Hybrid PQ key exchange":
        primitive = "combiner"
    props: Dict[str, object] = {"primitive": primitive, "cryptoFunctions": functions}

    param = _parameter_set(algorithm, findings)
    if param:
        props["parameterSetIdentifier"] = param
        props["nistQuantumSecurityLevel"] = _PARAM_LEVELS[algorithm][param]
    elif algorithm in _LEVELS:
        props["nistQuantumSecurityLevel"] = _LEVELS[algorithm]
    elif first.quantum in ("shor", "classic"):
        props["nistQuantumSecurityLevel"] = 0

    worst = min(findings, key=lambda f: f.sort_key())
    properties = [
        {"name": "pqscan:risk", "value": worst.risk},
        {"name": "pqscan:quantumThreat", "value": first.quantum},
        {"name": "pqscan:occurrences", "value": str(len(findings))},
    ]
    if worst.priority:
        properties.append({"name": "pqscan:migrationPriority", "value": str(worst.priority)})
    if first.replace_with:
        properties.append({"name": "pqscan:recommendedReplacement", "value": first.replace_with})

    occurrences = []
    for f in findings:
        occ = {"location": f.path, "line": f.line}
        context = f.detail if f.context in ("certificate", "key") else f.snippet
        if context:
            occ["additionalContext"] = context[:300]
        occurrences.append(occ)

    return {
        "type": "cryptographic-asset",
        "bom-ref": "crypto/algorithm/" + _slug(algorithm),
        "name": algorithm,
        "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": props},
        "evidence": {"occurrences": occurrences},
        "properties": properties,
    }


def _protocol_component(algorithm: str, findings: List[Finding]) -> dict:
    version = algorithm[4:] if algorithm.startswith("TLS ") else algorithm
    return {
        "type": "cryptographic-asset",
        "bom-ref": "crypto/protocol/" + _slug(algorithm),
        "name": algorithm,
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": {"type": "tls", "version": version},
        },
        "evidence": {"occurrences": [{"location": f.path, "line": f.line} for f in findings]},
        "properties": [
            {"name": "pqscan:risk", "value": findings[0].risk},
            {"name": "pqscan:recommendedReplacement", "value": findings[0].replace_with},
        ],
    }


def _certificate_component(index: int, cert: dict, algorithm_refs: Dict[str, str]) -> dict:
    cprops: Dict[str, object] = {"certificateFormat": "X.509"}
    if cert.get("subject"):
        cprops["subjectName"] = cert["subject"]
    if cert.get("issuer"):
        cprops["issuerName"] = cert["issuer"]
    if cert.get("not_before"):
        cprops["notValidBefore"] = cert["not_before"] + "T00:00:00Z"
    if cert.get("not_after"):
        cprops["notValidAfter"] = cert["not_after"] + "T00:00:00Z"

    key = cert["key_algorithm"]
    if cert.get("key_bits") and str(cert["key_bits"]) not in key:
        key = "%s-%d" % (key, cert["key_bits"])
    return {
        "type": "cryptographic-asset",
        "bom-ref": "crypto/certificate/%d" % index,
        "name": cert.get("subject") or os.path.basename(cert["path"]),
        "cryptoProperties": {"assetType": "certificate", "certificateProperties": cprops},
        "evidence": {"occurrences": [{"location": cert["path"], "line": cert["line"]}]},
        "properties": [
            {"name": "pqscan:publicKey", "value": key},
            {"name": "pqscan:signatureAlgorithm", "value": cert.get("signature_algorithm", "")},
            {"name": "pqscan:quantumSafe", "value": "true" if cert.get("quantum_safe") else "false"},
        ],
    }


def _library_component(dep) -> dict:
    comp = {
        "type": "library",
        "bom-ref": "library/%s/%s/%s" % (dep.ecosystem, _slug(dep.library), _slug(dep.path)),
        "name": dep.library,
        "description": dep.note,
        "properties": [
            {"name": "pqscan:manifest", "value": dep.path},
            {"name": "pqscan:ecosystem", "value": dep.ecosystem},
            {"name": "pqscan:postQuantumLibrary", "value": "true" if dep.pqc else "false"},
        ],
    }
    if dep.pq_path:
        comp["properties"].append({"name": "pqscan:postQuantumPath", "value": dep.pq_path})
    exact = re.match(r"^(?:==|=|v)?\s*([0-9][A-Za-z0-9.+_-]*)$", dep.version or "")
    if exact:
        comp["version"] = exact.group(1)
        purl_type = _ECOSYSTEM_PURL.get(dep.ecosystem)
        if purl_type and "/" not in dep.library.lstrip("@"):
            comp["purl"] = "pkg:%s/%s@%s" % (purl_type, dep.library.lower(), exact.group(1))
    elif dep.version:
        comp["properties"].append({"name": "pqscan:versionSpec", "value": dep.version})
    return comp


def render_cbom(result: ScanResult) -> dict:
    """Return a CycloneDX 1.6 CBOM as a dict ready for json.dump."""
    grouped: Dict[str, List[Finding]] = {}
    for f in result.active:
        grouped.setdefault(f.algorithm, []).append(f)

    components = []
    refs: Dict[str, str] = {}
    for algorithm in sorted(grouped, key=lambda a: grouped[a][0].sort_key()):
        findings = sorted(grouped[algorithm], key=lambda f: (f.path, f.line))
        if findings[0].family == "protocol":
            comp = _protocol_component(algorithm, findings)
        else:
            comp = _algorithm_component(algorithm, findings)
        refs[algorithm] = comp["bom-ref"]
        components.append(comp)

    for i, cert in enumerate(result.certificates, start=1):
        components.append(_certificate_component(i, cert, refs))

    seen = set()
    for dep in result.dependencies:
        comp = _library_component(dep)
        if comp["bom-ref"] not in seen:
            seen.add(comp["bom-ref"])
            components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
                         .replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {
                "components": [
                    {"type": "application", "name": "pqscan", "version": __version__}
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "scan-target",
                "name": os.path.basename(result.root.rstrip(os.sep)) or result.root,
            },
            "properties": [
                {"name": "pqscan:policy", "value": result.policy},
                {"name": "pqscan:filesScanned", "value": str(result.files_scanned)},
                {"name": "pqscan:mentionsIncluded",
                 "value": "true" if result.include_mentions else "false"},
            ],
        },
        "components": components,
    }
