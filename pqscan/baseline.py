"""
Baselines: adopt the scanner on an existing codebase without drowning.

A baseline is a list of finding fingerprints. With --baseline, findings that
are already in the file are marked as known, and --fail-on only looks at the
new ones. That lets a team gate pull requests on "no new quantum-vulnerable
crypto" on day one, and burn the existing debt down separately.

Fingerprints are built from the file path, the algorithm and the text of the
line, not the line number, so they survive unrelated edits above the finding.
"""

from __future__ import annotations

import json
from typing import Set

from .scanner import GENERATED_MARKER, ScanResult


def write_baseline(result: ScanResult, path: str) -> int:
    prints = sorted({f.fingerprint for f in result.findings if not f.mention})
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"generator": GENERATED_MARKER, "kind": "baseline",
                   "version": 1, "fingerprints": prints}, fh, indent=2)
        fh.write("\n")
    return len(prints)


def load_baseline(path: str) -> Set[str]:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "fingerprints" in data:
        return set(data["fingerprints"])
    # a --json findings file from an earlier run works as a baseline too
    if isinstance(data, dict) and "findings" in data:
        return {f.get("fingerprint", "") for f in data["findings"]} - {""}
    raise ValueError("not a pqscan baseline or findings file: " + path)


def apply_baseline(result: ScanResult, fingerprints: Set[str]) -> int:
    """Mark known findings; return the number of new ones."""
    new = 0
    for f in result.findings:
        f.is_new = f.fingerprint not in fingerprints
        if f.is_new and not f.mention:
            new += 1
    result.baseline_used = True
    return new
