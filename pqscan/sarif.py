"""
SARIF 2.1.0 output.

SARIF is what GitHub code scanning, GitLab, Azure DevOps and most IDE plugins
ingest. Uploading this file puts each finding inline on the pull request that
introduced it.

Post-quantum-safe findings are inventory, not problems, so they are left out.
"""

from __future__ import annotations

from typing import Dict, List
from urllib.parse import quote

from . import PROJECT_URL, __version__
from .rules import RISK_LABELS, RULES
from .scanner import GENERATED_MARKER, ScanResult

_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
          "low": "note", "info": "note"}
_SEVERITY = {"critical": "9.0", "high": "7.0", "medium": "5.0",
             "low": "3.0", "info": "1.0", "safe": "0.0"}
_QUANTUM = {
    "shor": "Broken by Shor's algorithm on a cryptographically relevant quantum computer.",
    "grover": "Weakened, not broken, by Grover's algorithm.",
    "classic": "Weak against classical attacks today.",
    "safe": "Post-quantum safe.",
}


def _rule_entry(rule) -> dict:
    text = "%s: %s %s" % (rule.algorithm, _QUANTUM[rule.quantum], rule.note)
    help_text = text.strip()
    if rule.replace_with:
        help_text += " Recommended replacement: %s." % rule.replace_with
    return {
        "id": rule.id,
        "name": "".join(ch for ch in rule.algorithm.title() if ch.isalnum()) + "Usage",
        "shortDescription": {"text": "%s (%s)" % (rule.algorithm, RISK_LABELS[rule.risk].lower())},
        "fullDescription": {"text": text.strip()},
        "help": {"text": help_text},
        "defaultConfiguration": {"level": _LEVEL.get(rule.risk, "none")},
        "properties": {
            "tags": ["security", "cryptography", "post-quantum", rule.family],
            "security-severity": _SEVERITY[rule.risk],
        },
    }


def render_sarif(result: ScanResult) -> dict:
    findings = [f for f in result.active if f.risk != "safe"]
    used = {f.rule_id for f in findings}
    rules = [r for r in RULES if r.id in used]
    index: Dict[str, int] = {r.id: i for i, r in enumerate(rules)}

    results: List[dict] = []
    for f in findings:
        message = "%s found (%s)." % (f.algorithm, RISK_LABELS[f.risk].lower())
        if f.detail:
            message += " " + f.detail + "."
        if f.note:
            message += " " + f.note
        if f.replace_with:
            message += " Replace with: %s." % f.replace_with
        entry = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": _LEVEL.get(f.risk, "note"),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": quote(f.path), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(f.line, 1), "startColumn": max(f.col, 1)},
                }
            }],
            "partialFingerprints": {"pqscan/v1": f.fingerprint},
            "properties": {
                "risk": f.risk,
                "migrationPriority": f.priority,
                "context": f.context,
            },
        }
        if result.baseline_used:
            entry["baselineState"] = "new" if f.is_new else "unchanged"
        results.append(entry)

    driver = {
        "name": "pqscan",
        "version": __version__,
        "properties": {"generator": GENERATED_MARKER},
        "rules": [_rule_entry(r) for r in rules],
    }
    if PROJECT_URL:
        driver["informationUri"] = PROJECT_URL

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver},
            "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The scanned directory."}}},
            "results": results,
        }],
    }
