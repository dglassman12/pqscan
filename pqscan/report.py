"""
Human-readable reports: the terminal summary and the Markdown report.

The CBOM (cbom.py), SARIF (sarif.py) and HTML (htmlreport.py) outputs live in
their own modules. render_cbom is re-exported here for backwards compatibility.
"""

from __future__ import annotations

import datetime
import os
import sys
from typing import List

from . import PROJECT_URL, __version__
from .cbom import render_cbom  # noqa: F401  (re-export)
from .rules import POLICIES, RISK_LABELS
from .scanner import GENERATED_MARKER, Finding, ScanResult
from .summary import DEADLINE_SOURCE, Summary, priority_rows, risk_rows, summarise

# ----------------------------------------------------------------------
# Terminal
# ----------------------------------------------------------------------

_ANSI = {
    "critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m",
    "low": "\033[36m", "info": "\033[34m", "safe": "\033[32m",
    "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m",
}


def use_color(stream=None, disabled: bool = False) -> bool:
    stream = stream or sys.stdout
    if disabled or os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


def _plural(count: int, singular: str, plural: str = None) -> str:
    word = singular if count == 1 else (plural or singular + "s")
    return f"{count:,} {word}"


def _bar(count: int, top: int, width: int = 24) -> str:
    if top <= 0:
        return ""
    filled = max(1, round(width * count / top)) if count else 0
    return "█" * filled


def render_console(result: ScanResult, color: bool = False, top_files: int = 5) -> str:
    def c(key: str, text: str) -> str:
        return f"{_ANSI[key]}{text}{_ANSI['reset']}" if color else text

    s = summarise(result)
    out: List[str] = []
    add = out.append

    add(f"Scanned {_plural(result.files_scanned, 'file')} in {result.elapsed:.1f}s "
        f"({result.files_skipped:,} skipped), policy: {result.policy}")
    add("")

    if not s.total and not result.dependencies:
        add("No cryptography detected. That means nothing matched the rules, "
            "not that there is none.")
        return "\n".join(out)

    headline = (f"{_plural(s.pk_vulnerable, 'quantum-vulnerable usage')} "
                f"in {_plural(s.files_with_findings, 'file')}")
    add(c("critical" if s.pk_vulnerable else "safe", headline))
    if s.pk_vulnerable or s.pk_safe:
        add(f"Public-key crypto migrated to post-quantum: {s.migrated_pct}% "
            f"({s.pk_safe:,} of {s.pk_vulnerable + s.pk_safe:,})")
    add("")

    for risk, count in risk_rows(s):
        add(f"  {c(risk, f'{risk:<9}')} {count:>6,}  {c('dim', RISK_LABELS[risk])}")
    add("")

    if s.pk_vulnerable:
        parts = []
        for label, date, days, _text in s.deadlines:
            left = f"{days / 365.25:.1f} years left" if days > 0 else "passed"
            parts.append(f"{label.split()[0].lower()} after {date[:4]} ({left})")
        add(c("dim", f"{DEADLINE_SOURCE}: quantum-vulnerable public-key crypto is "
                     + ", ".join(parts)))
        add("")

    if s.by_algorithm:
        add(c("bold", "By algorithm"))
        top = max(n for _, n, _ in s.by_algorithm)
        for algo, count, risk in s.by_algorithm:
            if risk == "safe":
                continue
            add(f"  {algo:<36} {count:>6,}  {c(risk, _bar(count, top))}")
        safe = [(a, n) for a, n, r in s.by_algorithm if r == "safe"]
        if safe:
            listed = ", ".join(f"{a} ({n:,})" for a, n in safe)
            add(f"  {c('safe', 'safe:')} {listed}")
        add("")

    tiers = list(priority_rows(s))
    if tiers:
        add(c("bold", "Fix first"))
        for number, title, _guidance, items in tiers:
            add(f"  {number}. {title:<36} {len(items):>6,}")
        add("")

    if s.hot_files:
        add(c("bold", "Hotspots"))
        for path, crit, high, total in s.hot_files[:top_files]:
            add(f"  {total:>5,}  {path}  {c('dim', f'({crit} critical, {high} high)')}")
        if len(s.hot_files) > top_files:
            add(c("dim", f"         ...and {len(s.hot_files) - top_files:,} more files"))
        add("")

    if result.certificates:
        add(c("bold", f"Certificates: {len(result.certificates):,}"))
        for cert in result.certificates[:top_files]:
            key = cert["key_algorithm"]
            if cert.get("key_bits") and str(cert["key_bits"]) not in key:
                key = f"{key}-{cert['key_bits']}"
            add(f"  {cert['path']}: {cert.get('subject') or '(no subject)'}, {key}, "
                f"expires {cert.get('not_after') or 'unknown'}")
        add("")

    if result.dependencies:
        add(c("bold", f"Crypto libraries: {len(result.dependencies):,}"))
        for dep in result.dependencies[:10]:
            tag = c("safe", " [post-quantum]") if dep.pqc else ""
            add(f"  {dep.library:<24} {dep.ecosystem:<9} {dep.path}{tag}")
        if len(result.dependencies) > 10:
            add(c("dim", f"  ...and {len(result.dependencies) - 10:,} more"))
        add("")

    notes = []
    if s.mentions:
        notes.append(f"{_plural(s.mentions, 'mention')} in comments and docs not counted "
                     f"(--include-mentions to count them)")
    if result.baseline_used:
        notes.append(f"{_plural(s.new, 'finding')} not in the baseline")
    if result.keystores:
        notes.append(f"{_plural(len(result.keystores), 'keystore')} could not be inspected")
    if result.oversized:
        notes.append(f"{_plural(len(result.oversized), 'file')} over the size limit skipped")
    if result.truncated:
        notes.append(f"{_plural(len(result.truncated), 'file')} had findings capped at the per-file limit")
    for note in notes:
        add(c("dim", "note: " + note))
    return "\n".join(out).rstrip()


# ----------------------------------------------------------------------
# Badge
# ----------------------------------------------------------------------

def render_badge(result: ScanResult) -> str:
    """A small SVG badge for a README: share of public-key crypto migrated."""
    s = summarise(result)
    label = "post-quantum"
    if s.pk_vulnerable + s.pk_safe == 0:
        value, color = "no public-key crypto found", "#7f8aa0"
    else:
        pct = s.migrated_pct
        value = f"{pct}% migrated"
        color = "#0ca30c" if pct >= 100 else "#3a8f3a" if pct >= 75 else \
                "#c98a00" if pct >= 25 else "#d03b3b"
    left = 14 + round(len(label) * 6.6)
    right = 14 + round(len(value) * 6.6)
    width = left + right
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        f'<!-- {GENERATED_MARKER} -->'
        f'<title>{label}: {value}</title>'
        f'<clipPath id="r"><rect width="{width}" height="20" rx="3"/></clipPath>'
        f'<g clip-path="url(#r)">'
        f'<rect width="{left}" height="20" fill="#3b4252"/>'
        f'<rect x="{left}" width="{right}" height="20" fill="{color}"/></g>'
        f'<g fill="#fff" text-anchor="middle" font-size="11" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif">'
        f'<text x="{left / 2:.1f}" y="14">{label}</text>'
        f'<text x="{left + right / 2:.1f}" y="14">{value}</text></g></svg>\n'
    )


# ----------------------------------------------------------------------
# Markdown
# ----------------------------------------------------------------------

def _cell(text) -> str:
    """Escape text for a Markdown table cell."""
    return str(text).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _code(text: str) -> str:
    """Inline code that survives backticks and pipes in the content."""
    text = str(text).replace("|", "\\|").replace("\n", " ")
    if "`" in text:
        return "`` " + text + " ``"
    return "`" + text + "`"


def _key_label(cert: dict) -> str:
    key = cert["key_algorithm"]
    if cert.get("key_bits") and str(cert["key_bits"]) not in key:
        key = f"{key}-{cert['key_bits']}"
    return key


def render_markdown(result: ScanResult, top_n: int = 25) -> str:
    top_n = max(0, top_n)
    s: Summary = summarise(result)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines: List[str] = []
    add = lines.append

    add(f"<!-- {GENERATED_MARKER}: this file is skipped by later scans -->")
    add("# Cryptographic Inventory Report")
    add("")
    add(f"**Target:** `{os.path.basename(result.root.rstrip(os.sep)) or result.root}`  ")
    add(f"**Generated:** {now}  ")
    add(f"**Policy:** {result.policy}: {POLICIES.get(result.policy, '')}  ")
    add(f"**Files scanned:** {result.files_scanned:,}  ")
    add(f"**Findings:** {s.total:,}  ")
    add(f"**Certificates:** {len(result.certificates):,}  ")
    add(f"**Crypto libraries:** {len(result.dependencies):,}")
    add("")

    add("## Summary")
    add("")
    if s.total == 0 and not result.dependencies:
        add("No cryptographic identifiers or crypto dependencies were detected. "
            "This does not mean the target is free of cryptography, only that "
            "nothing matched the scanner's rules. Manual review is still required.")
        add("")
        return "\n".join(lines)

    add(f"The scan found **{_plural(s.pk_vulnerable, 'use')} of quantum-vulnerable "
        f"public-key cryptography** across {_plural(s.files_with_findings, 'file')}, "
        f"plus {_plural(s.actionable - s.pk_vulnerable, 'other item')} that "
        f"need attention.")
    if s.pk_vulnerable or s.pk_safe:
        add(f"**{s.migrated_pct}%** of public-key usage ({s.pk_safe:,} of "
            f"{s.pk_vulnerable + s.pk_safe:,}) is already post-quantum or hybrid.")
    add("")
    add("| Risk | Count | Meaning |")
    add("|---|---:|---|")
    for risk, count in risk_rows(s):
        add(f"| {risk} | {count:,} | {RISK_LABELS[risk]} |")
    add("")
    if result.baseline_used:
        add(f"Compared against a baseline: **{_plural(s.new, 'finding')}** "
            f"{'is' if s.new == 1 else 'are'} new.")
        add("")

    add("### Deadlines")
    add("")
    add("| Milestone | Date | Time left |")
    add("|---|---|---|")
    for label, date, days, _text in s.deadlines:
        left = f"{days / 365.25:.1f} years" if days > 0 else "passed"
        add(f"| {label} | after {date} | {left} |")
    add("")
    add(f"Dates are from {DEADLINE_SOURCE} and apply to quantum-vulnerable "
        f"public-key algorithms (the critical findings). Check the current "
        f"text before planning against them.")
    add("")

    add("## What to fix first")
    add("")
    add("Ordered by threat, not by count.")
    add("")
    for number, title, guidance, items in priority_rows(s):
        add(f"### {number}. {title} ({_plural(len(items), 'finding')})")
        add("")
        add(guidance)
        add("")
        counts = {}
        for f in items:
            counts[f.algorithm] = counts.get(f.algorithm, 0) + 1
        add("| Algorithm | Count | Replace with |")
        add("|---|---:|---|")
        seen = set()
        for f in sorted(items, key=lambda f: -counts[f.algorithm]):
            if f.algorithm in seen:
                continue
            seen.add(f.algorithm)
            add(f"| {_cell(f.algorithm)} | {counts[f.algorithm]:,} | {_cell(f.replace_with or f.note or '')} |")
        add("")

    if s.hot_areas:
        add("## Where it lives")
        add("")
        add("Findings by top-level directory. Priority 1 is key establishment "
            "and encryption, 2 is signatures, 3 is classically weak, 4 is policy.")
        add("")
        add("| Area | P1 | P2 | P3 | P4 | Total |")
        add("|---|---:|---:|---:|---:|---:|")
        for area, bucket, total in s.hot_areas[:15]:
            add(f"| {_code(area)} | {bucket.get(1, 0):,} | {bucket.get(2, 0):,} | "
                f"{bucket.get(3, 0):,} | {bucket.get(4, 0):,} | {total:,} |")
        add("")
        add("| File | Critical | High | Total |")
        add("|---|---:|---:|---:|")
        for path, crit, high, total in s.hot_files[:10]:
            add(f"| {_code(path)} | {crit:,} | {high:,} | {total:,} |")
        if len(s.hot_files) > 10:
            add("")
            add(f"*{len(s.hot_files) - 10:,} more files have findings.*")
        add("")

    if result.certificates:
        add("## Certificates")
        add("")
        add("Parsed from PEM and DER files. A certificate that outlives a "
            "deadline above has to be reissued with a post-quantum key before then.")
        add("")
        add("| File | Subject | Key | Signature | Expires |")
        add("|---|---|---|---|---|")
        for cert in result.certificates:
            add(f"| {_code(cert['path'])} | {_cell(cert.get('subject') or '')} | "
                f"{_cell(_key_label(cert))} | {_cell(cert.get('signature_algorithm') or '')} | "
                f"{cert.get('not_after') or ''} |")
        add("")

    if result.dependencies:
        add("## Cryptographic dependencies")
        add("")
        add("Libraries that implement cryptography. A dependency is not a "
            "vulnerability, but each one is a place where quantum-vulnerable "
            "algorithms may be in use even if your own code never names them.")
        add("")
        add("| Ecosystem | Library | Version | Manifest | Note | Post-quantum path |")
        add("|---|---|---|---|---|---|")
        for d in result.dependencies:
            path = "Already a post-quantum library" if d.pqc else d.pq_path
            add(f"| {d.ecosystem} | {_code(d.library)} | {_cell(d.version)} | "
                f"{_code(d.path)} | {_cell(d.note)} | {_cell(path)} |")
        add("")

    actionable = [f for f in result.active if f.risk != "safe"]
    if actionable:
        shown = actionable[:top_n]
        add(f"## Findings ({len(shown):,} of {len(actionable):,})")
        add("")
        if shown:
            add("| Risk | Algorithm | Location | Context | Detail |")
            add("|---|---|---|---|---|")
            for f in shown:
                detail = f.detail if f.context in ("certificate", "key") else f.snippet
                if len(detail) > 90:
                    detail = detail[:87] + "..."
                new = " (new)" if result.baseline_used and f.is_new else ""
                add(f"| {f.risk}{new} | {_cell(f.algorithm)} | {_code(f'{f.path}:{f.line}')} | "
                    f"{f.context} | {_code(detail) if detail else ''} |")
        if len(actionable) > len(shown):
            add("")
            add(f"*{len(actionable) - len(shown):,} more findings not shown. "
                f"The HTML report, CBOM and JSON output have the full set.*")
        add("")

    safe = [(a, n) for a, n, r in s.by_algorithm if r == "safe"]
    if safe:
        add("## Already post-quantum safe")
        add("")
        add("Recorded for inventory completeness. No action needed.")
        add("")
        add("| Algorithm | Count |")
        add("|---|---:|")
        for algo, count in safe:
            add(f"| {_cell(algo)} | {count:,} |")
        add("")

    notes = []
    if s.mentions:
        notes.append(f"{_plural(s.mentions, 'match')} in comments and documentation "
                     f"{'was' if s.mentions == 1 else 'were'} left out of the counts. "
                     f"Run with `--include-mentions` to count them.")
    if result.keystores:
        notes.append(f"{_plural(len(result.keystores), 'keystore')} could not be inspected "
                     f"(encrypted containers): " + ", ".join(_code(k) for k in result.keystores[:10]))
    if result.oversized:
        notes.append(f"{_plural(len(result.oversized), 'file')} over the size limit "
                     f"{'was' if len(result.oversized) == 1 else 'were'} skipped: "
                     + ", ".join(_code(k) for k in result.oversized[:10]))
    if result.truncated:
        notes.append("Findings were capped in: " + ", ".join(_code(k) for k in result.truncated[:10]))
    if notes:
        add("## Not covered")
        add("")
        for note in notes:
            add(f"- {note}")
        add("")

    add("---")
    add("")
    tool = f"[pqscan]({PROJECT_URL})" if PROJECT_URL else "pqscan"
    add(f"Generated by {tool} v{__version__}. Static analysis only: it finds "
        f"names in source, config, certificates and manifests, not runtime "
        f"behaviour. Review the findings before treating this as a complete inventory.")
    add("")
    return "\n".join(lines)
