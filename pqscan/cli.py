"""Command line interface for pqscan."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .baseline import apply_baseline, load_baseline, write_baseline
from .cbom import render_cbom
from .htmlreport import render_html
from .report import render_badge, render_console, render_markdown, use_color
from .rules import POLICIES, RISK_ORDER, RULES
from .sarif import render_sarif
from .scanner import DEFAULT_MAX_FILE_BYTES, scan_path

FAIL_LEVELS = ("critical", "high", "medium", "low")

EPILOG = """\
examples:
  pqscan .                                   summary in the terminal
  pqscan . --html report.html                interactive report
  pqscan . -o report.md --cbom cbom.json     Markdown report and CycloneDX CBOM
  pqscan . --sarif pqscan.sarif              for GitHub code scanning
  pqscan . --write-baseline .pqscan-baseline.json
  pqscan . --baseline .pqscan-baseline.json --fail-on critical
                                             fail CI only on new critical findings

suppress a line with a trailing comment:    # pqscan: ignore
exclude paths with --exclude or a .pqscanignore file (one glob per line)
"""


def _non_negative(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return number


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pqscan",
        description="Inventory the cryptography in a codebase and rank it for "
                    "post-quantum migration.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("path", nargs="?", help="directory to scan")

    out = p.add_argument_group("reports")
    out.add_argument("-o", "--output", metavar="FILE", help="write a Markdown report")
    out.add_argument("--html", metavar="FILE", help="write an interactive HTML report")
    out.add_argument("--cbom", metavar="FILE", help="write a CycloneDX 1.6 CBOM (JSON)")
    out.add_argument("--sarif", metavar="FILE", help="write SARIF 2.1.0 for code-scanning tools")
    out.add_argument("--json", metavar="FILE", help="write raw findings as JSON")
    out.add_argument("--badge", metavar="FILE",
                     help="write an SVG badge showing the share already migrated")
    out.add_argument("--top", type=_non_negative, default=25, metavar="N",
                     help="detailed findings in the Markdown report (default 25)")
    out.add_argument("-q", "--quiet", action="store_true", help="no terminal summary")
    out.add_argument("--no-color", action="store_true", help="plain terminal output")

    scan = p.add_argument_group("scanning")
    scan.add_argument("--policy", choices=sorted(POLICIES), default="nist",
                      help="risk policy: nist (default) or cnsa2 (stricter)")
    scan.add_argument("--include-mentions", action="store_true",
                      help="count matches in comments and documentation too")
    scan.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                      help="skip paths matching this glob (repeatable)")
    scan.add_argument("--skip-tests", action="store_true",
                      help="leave out test directories and test files")
    scan.add_argument("--max-file-size", type=float, metavar="MB",
                      default=DEFAULT_MAX_FILE_BYTES / 1_000_000,
                      help="skip files larger than this (default 5)")

    ci = p.add_argument_group("CI")
    ci.add_argument("--fail-on", choices=FAIL_LEVELS, metavar="LEVEL",
                    help="exit 1 if any finding is at this risk or worse "
                         "(critical, high, medium, low)")
    ci.add_argument("--fail-on-critical", action="store_true",
                    help="same as --fail-on critical")
    ci.add_argument("--baseline", metavar="FILE",
                    help="known findings; --fail-on then only counts new ones")
    ci.add_argument("--write-baseline", metavar="FILE",
                    help="save the current findings as a baseline")

    p.add_argument("--list-rules", action="store_true", help="print the rule set and exit")
    p.add_argument("--version", action="version", version=f"pqscan {__version__}")
    return p


def _list_rules() -> str:
    lines = [f"{'ID':<14}{'ALGORITHM':<38}{'RISK':<10}{'THREAT':<9}REPLACEMENT"]
    for rule in sorted(RULES, key=lambda r: (RISK_ORDER[r.risk], r.id)):
        lines.append(f"{rule.id:<14}{rule.algorithm:<38}{rule.risk:<10}"
                     f"{rule.quantum:<9}{rule.replace_with or '-'}")
    return "\n".join(lines)


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_rules:
        print(_list_rules())
        return 0
    if not args.path:
        parser.error("the following arguments are required: path")

    baseline = None
    if args.baseline:
        try:
            baseline = load_baseline(args.baseline)
        except (OSError, ValueError) as exc:
            print(f"error: cannot read baseline: {exc}", file=sys.stderr)
            return 2

    # Never scan our own output: a report written into the scanned directory
    # must not show up as findings on the next run.
    outputs = [args.output, args.html, args.cbom, args.sarif, args.json,
               args.badge, args.baseline, args.write_baseline]

    try:
        result = scan_path(
            args.path,
            policy=args.policy,
            excludes=args.exclude,
            skip_paths=[p for p in outputs if p],
            max_file_bytes=int(args.max_file_size * 1_000_000),
            include_mentions=args.include_mentions,
            skip_tests=args.skip_tests,
        )
    except NotADirectoryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if baseline is not None:
        apply_baseline(result, baseline)

    written = []
    try:
        if args.output:
            _write(args.output, render_markdown(result, top_n=args.top))
            written.append(("Markdown report", args.output))
        if args.html:
            _write(args.html, render_html(result))
            written.append(("HTML report", args.html))
        if args.cbom:
            _write(args.cbom, json.dumps(render_cbom(result), indent=2) + "\n")
            written.append(("CycloneDX CBOM", args.cbom))
        if args.sarif:
            _write(args.sarif, json.dumps(render_sarif(result), indent=2) + "\n")
            written.append(("SARIF", args.sarif))
        if args.json:
            _write(args.json, json.dumps(result.as_dict(), indent=2) + "\n")
            written.append(("Raw findings", args.json))
        if args.badge:
            _write(args.badge, render_badge(result))
            written.append(("Badge", args.badge))
        if args.write_baseline:
            count = write_baseline(result, args.write_baseline)
            written.append((f"Baseline ({count:,} findings)", args.write_baseline))
    except OSError as exc:
        print(f"error: cannot write output: {exc}", file=sys.stderr)
        return 2

    if not args.quiet:
        print(render_console(result, color=use_color(disabled=args.no_color)))
        if written:
            print()
            width = max(len(label) for label, _ in written)
            for label, path in written:
                print(f"{label:<{width}}  ->  {path}")

    level = args.fail_on or ("critical" if args.fail_on_critical else None)
    if level:
        threshold = RISK_ORDER[level]
        failing = [f for f in result.active
                   if RISK_ORDER[f.risk] <= threshold and (baseline is None or f.is_new)]
        if failing:
            if not args.quiet:
                scope = "new " if baseline is not None else ""
                print(f"\nFAIL: {len(failing):,} {scope}finding"
                      f"{'' if len(failing) == 1 else 's'} at {level} or worse.",
                      file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
