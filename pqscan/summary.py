"""
Aggregations shared by every report format.

Counting findings is the easy part. The useful questions are "what do we fix
first" and "where does it live", so this module groups findings by migration
priority and by location.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from .rules import PRIORITY_LABELS, RISK_LEVELS, RISK_ORDER
from .scanner import Finding, ScanResult

# NIST IR 8547, "Transition to Post-Quantum Cryptography Standards": every
# quantum-vulnerable public-key algorithm is deprecated after 2030 and
# disallowed after 2035. Check the current text before relying on the dates.
DEADLINES = [
    ("Deprecated by NIST", datetime.date(2030, 12, 31),
     "Quantum-vulnerable public-key algorithms are deprecated after this date."),
    ("Disallowed by NIST", datetime.date(2035, 12, 31),
     "Quantum-vulnerable public-key algorithms are disallowed after this date."),
]
DEADLINE_SOURCE = "NIST IR 8547"


@dataclass
class Summary:
    total: int = 0
    by_risk: Dict[str, int] = field(default_factory=dict)
    by_algorithm: List[Tuple[str, int, str]] = field(default_factory=list)
    priorities: Dict[int, List[Finding]] = field(default_factory=dict)
    hot_files: List[Tuple[str, int, int, int]] = field(default_factory=list)
    hot_areas: List[Tuple[str, Dict[int, int], int]] = field(default_factory=list)
    files_with_findings: int = 0
    pk_vulnerable: int = 0          # quantum-vulnerable public-key usages
    pk_safe: int = 0                # post-quantum or hybrid public-key usages
    actionable: int = 0             # everything that is not "safe"
    mentions: int = 0
    new: int = 0
    deadlines: List[Tuple[str, str, int, str]] = field(default_factory=list)

    @property
    def migrated_pct(self) -> int:
        total = self.pk_vulnerable + self.pk_safe
        return round(100 * self.pk_safe / total) if total else 0


def _area(path: str) -> str:
    return path.split("/", 1)[0] if "/" in path else "(top level)"


def summarise(result: ScanResult, today: datetime.date = None) -> Summary:
    today = today or datetime.date.today()
    active = result.active
    s = Summary(total=len(active), mentions=0 if result.include_mentions else len(result.mentions))

    algo_risk: Dict[str, str] = {}
    algo_count: Dict[str, int] = {}
    files: Dict[str, List[int]] = {}
    areas: Dict[str, Dict[int, int]] = {}

    for f in active:
        s.by_risk[f.risk] = s.by_risk.get(f.risk, 0) + 1
        algo_count[f.algorithm] = algo_count.get(f.algorithm, 0) + 1
        prev = algo_risk.get(f.algorithm)
        if prev is None or RISK_ORDER[f.risk] < RISK_ORDER[prev]:
            algo_risk[f.algorithm] = f.risk
        if f.is_new:
            s.new += 1
        if f.risk == "safe":
            if f.family in ("kem", "signature", "key-agreement", "pke"):
                s.pk_safe += 1
            continue
        s.actionable += 1
        if f.quantum == "shor":
            s.pk_vulnerable += 1
        if f.priority:
            s.priorities.setdefault(f.priority, []).append(f)
            bucket = areas.setdefault(_area(f.path), {})
            bucket[f.priority] = bucket.get(f.priority, 0) + 1
        row = files.setdefault(f.path, [0, 0, 0])
        row[2] += 1
        if f.risk == "critical":
            row[0] += 1
        elif f.risk == "high":
            row[1] += 1

    s.by_algorithm = sorted(
        ((a, c, algo_risk[a]) for a, c in algo_count.items()),
        key=lambda t: (RISK_ORDER[t[2]], -t[1], t[0]),
    )
    s.files_with_findings = len(files)
    s.hot_files = sorted(
        ((p, r[0], r[1], r[2]) for p, r in files.items()),
        key=lambda t: (-t[1], -t[2], -t[3], t[0]),
    )
    s.hot_areas = sorted(
        ((a, b, sum(b.values())) for a, b in areas.items()),
        key=lambda t: (-t[1].get(1, 0), -t[1].get(2, 0), -t[2], t[0]),
    )
    for label, date, text in DEADLINES:
        s.deadlines.append((label, date.isoformat(), (date - today).days, text))
    return s


def risk_rows(summary: Summary) -> List[Tuple[str, int]]:
    return [(r, summary.by_risk[r]) for r in RISK_LEVELS if summary.by_risk.get(r)]


def priority_rows(summary: Summary):
    """Yield (number, title, guidance, findings) for each non-empty tier."""
    for n in sorted(PRIORITY_LABELS):
        items = summary.priorities.get(n)
        if items:
            title, guidance = PRIORITY_LABELS[n]
            yield n, title, guidance, items
