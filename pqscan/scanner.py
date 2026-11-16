"""
File walking, rule matching and context classification.

The scanner is still a static, pattern-based tool: it reads text and finds
names. What it adds on top of plain grep is the part that decides whether a
match is worth a human's attention:

  * long base64 blobs are masked first, so random key material cannot spell
    "RSA" or "md5" by accident
  * overlapping matches are resolved longest-first, so "ML-DSA" is never
    reported as "DSA"
  * short ambiguous tokens only count in files that look like crypto
  * every match is tagged with its context (code, config, comment, doc), and
    comments and documentation are kept apart from real findings
  * certificates and keys are parsed, not just pattern-matched

False positives are still possible. The output is an inventory to be reviewed
by a human, not a certified audit.
"""

from __future__ import annotations

import bisect
import fnmatch
import hashlib
import os
import re
import time
from dataclasses import dataclass, asdict, field
from typing import Dict, Iterable, List, Optional, Tuple

from . import certs
from .deps import Dependency, is_manifest, parse_manifest
from .rules import (RULES, RULES_BY_ID, RISK_ORDER, Rule, apply_policy,
                    priority_for)

# Every report carries this marker so a later scan skips it. It is assembled
# here so that this source file does not contain the marker itself.
GENERATED_MARKER = "pqscan-" + "generated"
IGNORE_MARKER = re.compile(r"pqscan:\s*ignore(?!-file)")
IGNORE_FILE_MARKER = re.compile(r"pqscan:\s*ignore-file")
IGNORE_FILE_NAME = ".pqscanignore"

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "__pycache__",
    ".venv", "venv", "env", "dist", "build", "target", ".next",
    ".nuxt", "coverage", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".tox", "bower_components", ".idea", ".vscode", ".gradle", ".terraform",
    "site-packages", "dist-packages", ".cache", ".eggs",
}
SKIP_DIR_SUFFIXES = (".dist-info", ".egg-info")

# Paths that hold tests and fixtures (used by --skip-tests).
TEST_DIRS = {"test", "tests", "__tests__", "testdata", "testing", "spec", "specs",
             "fixtures", "__fixtures__", "__mocks__", "e2e"}
_TEST_FILE = re.compile(
    r"(?:^test_.*\.py$|_test\.(?:py|go|rb|rs|c|cc|cpp)$|^conftest\.py$|"
    r"\.(?:test|spec)\.[cm]?[jt]sx?$|_spec\.rb$|"
    r"Tests?\.(?:java|kt|cs|scala|groovy|swift)$)"
)


def is_test_path(rel_posix: str) -> bool:
    parts = rel_posix.split("/")
    if any(part.lower() in TEST_DIRS for part in parts[:-1]):
        return True
    return bool(_TEST_FILE.search(parts[-1]))


# Lockfiles are wall-to-wall integrity hashes, not crypto usage.
SKIP_FILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "pipfile.lock", "cargo.lock", "go.sum", "composer.lock",
    "gemfile.lock", "uv.lock", "flake.lock", "packages.lock.json",
    "gradle.lockfile", "mix.lock", "pubspec.lock", IGNORE_FILE_NAME,
}
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".sarif")

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff", ".psd",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".tar", ".zst",
    ".jar", ".war", ".ear", ".class", ".pyc", ".pyo", ".so", ".dll", ".dylib",
    ".exe", ".o", ".a", ".lib", ".obj", ".wasm", ".bin", ".img", ".iso",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac", ".ogg", ".webm",
    ".db", ".sqlite", ".sqlite3", ".parquet", ".npy", ".npz", ".pkl", ".h5",
}
DER_EXT = {".der", ".cer", ".crt", ".cert"}
KEYSTORE_EXT = {".p12", ".pfx", ".jks", ".keystore", ".bks", ".jceks", ".kdbx"}

DOC_EXT = {".md", ".markdown", ".rst", ".txt", ".adoc", ".asciidoc", ".org", ".tex"}
DOC_NAMES = {"readme", "license", "licence", "changelog", "changes", "notice",
             "authors", "contributing", "copying", "history", "news", "todo"}
CONFIG_EXT = {
    ".yaml", ".yml", ".json", ".toml", ".ini", ".conf", ".cfg", ".cnf",
    ".config", ".env", ".properties", ".xml", ".tf", ".tfvars", ".hcl",
    ".plist", ".service", ".j2", ".tpl", ".tmpl",
}

_HASH = {
    ".py", ".pyi", ".sh", ".bash", ".zsh", ".fish", ".rb", ".pl", ".pm",
    ".yaml", ".yml", ".toml", ".conf", ".cfg", ".cnf", ".ini", ".tf",
    ".tfvars", ".hcl", ".env", ".properties", ".r", ".ps1", ".psm1",
    ".cmake", ".nix", ".ex", ".exs", ".tcl", ".awk", ".mk", ".service",
    ".j2", ".gemspec", ".php",
}
_HASH_NAMES = {"dockerfile", "makefile", "gemfile", "rakefile", "vagrantfile",
               "procfile", "caddyfile", "pipfile", "brewfile", "sshd_config",
               "ssh_config", "authorized_keys", "known_hosts", "config"}
CONFIG_NAMES = {"sshd_config", "ssh_config", "dockerfile", "caddyfile"}
_SLASH = {
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".java", ".js", ".jsx",
    ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".kt", ".kts", ".swift",
    ".scala", ".cs", ".php", ".dart", ".gradle", ".groovy", ".m", ".mm",
    ".proto", ".sol", ".zig", ".v", ".sv", ".jsonc", ".json5", ".less",
    ".scss", ".css",
}
_DASH = {".sql", ".lua", ".hs", ".ada", ".adb", ".ads", ".elm", ".vhd"}
_XML = {".xml", ".html", ".htm", ".xhtml", ".vue", ".svelte", ".svg",
        ".plist", ".csproj", ".xaml"}
_SEMI = {".ini", ".asm", ".lisp", ".clj", ".el", ".scm"}

DEFAULT_MAX_FILE_BYTES = 5_000_000
MAX_SNIPPET = 160
MAX_FINDINGS_PER_FILE = 400
MAX_HITS_PER_FILE = 20_000        # a data file that matches on every line

# Long base64 / base64url runs (hashes, tokens, key material). Whether a run is
# data or a long identifier is decided by _is_blob below.
_BLOB = re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}")
_PEM_BODY = re.compile(r"(-----BEGIN [A-Z0-9 ]+-----)(.*?)(-----END [A-Z0-9 ]+-----)", re.S)

# General crypto vocabulary. A weak token ("rsa", "DES", "P-256") is only
# reported when its file contains one of these or a strong match.
_CONTEXT = re.compile(
    r"crypt|cipher|openssl|(?<![a-z])(?:ssl|tls)(?![a-z])|x\.?509|certificat|"
    r"key[_ -]?pair|private[_ -]?key|public[_ -]?key|signature|hashlib|digest|"
    r"(?<![a-z])jwt|(?<![a-z])ssh(?![a-z])|pkcs|hmac|keystore|keygen|handshake|"
    r"(?<![a-z])pem(?![a-z])|encrypt|decrypt|(?<![a-z])alg(?:o|orithm)?(?![a-z])|(?<![a-z])kex(?![a-z])|"
    r"(?<![a-z])keys?(?![a-z])|(?<![a-z])sign(?:s|ed|ing|er)?(?![a-z])"
)


@dataclass
class Finding:
    path: str
    line: int
    col: int
    rule_id: str
    algorithm: str
    family: str
    use: str
    quantum: str
    risk: str
    priority: int
    replace_with: str
    match: str
    snippet: str
    context: str            # code | config | comment | doc | certificate | key
    mention: bool           # True for comments and docs: not counted by default
    detail: str = ""
    note: str = ""
    fingerprint: str = ""
    is_new: bool = True     # False when present in the --baseline file

    def sort_key(self):
        return (RISK_ORDER.get(self.risk, 9), self.priority or 9, self.path, self.line)


@dataclass
class ScanResult:
    root: str
    policy: str
    files_scanned: int
    files_skipped: int
    findings: List[Finding]                       # everything, mentions included
    dependencies: List[Dependency] = field(default_factory=list)
    certificates: List[dict] = field(default_factory=list)
    keystores: List[str] = field(default_factory=list)
    oversized: List[str] = field(default_factory=list)
    truncated: List[str] = field(default_factory=list)
    elapsed: float = 0.0
    include_mentions: bool = False
    baseline_used: bool = False

    # ---- views -------------------------------------------------------
    @property
    def active(self) -> List[Finding]:
        """Findings that count: real usage, plus mentions if asked for."""
        if self.include_mentions:
            return self.findings
        return [f for f in self.findings if not f.mention]

    @property
    def mentions(self) -> List[Finding]:
        return [f for f in self.findings if f.mention]

    @property
    def counts_by_risk(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.active:
            counts[f.risk] = counts.get(f.risk, 0) + 1
        return counts

    @property
    def counts_by_algorithm(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.active:
            counts[f.algorithm] = counts.get(f.algorithm, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

    def as_dict(self) -> dict:
        return {
            "generator": GENERATED_MARKER,
            "root": self.root,
            "policy": self.policy,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "findings": [asdict(f) for f in self.findings],
            "dependencies": [asdict(d) for d in self.dependencies],
            "certificates": self.certificates,
            "keystores": self.keystores,
            "oversized": self.oversized,
        }


# ----------------------------------------------------------------------
# File classification
# ----------------------------------------------------------------------

def _file_kind(name: str) -> Tuple[str, frozenset]:
    """Return (kind, comment syntaxes) for a file name."""
    lower = name.lower()
    stem, ext = os.path.splitext(lower)
    if lower.startswith(".env"):
        ext = ".env"
    elif lower.startswith("dockerfile"):
        stem, ext = "dockerfile", ""
    syntax = set()
    if ext in _HASH or stem in _HASH_NAMES or lower in _HASH_NAMES:
        syntax.add("hash")
    if ext in _SLASH:
        syntax.add("slash")
    if ext in _DASH:
        syntax.add("dash")
    if ext in _XML:
        syntax.add("xml")
    if ext in _SEMI:
        syntax.add("semi")
    if ext in (".py", ".pyi"):
        syntax.add("pydoc")

    if ext in DOC_EXT or stem in DOC_NAMES:
        kind = "doc"
    elif ext in CONFIG_EXT or stem in CONFIG_NAMES:
        kind = "config"
    else:
        kind = "code"
    return kind, frozenset(syntax)


def _in_string(line: str, pos: int) -> bool:
    head = line[:pos]
    return (head.count('"') - head.count('\\"')) % 2 == 1 or \
           (head.count("'") - head.count("\\'")) % 2 == 1


def _comment_col(line: str, syntax: frozenset) -> int:
    """Column where a trailing comment starts, or a huge number if none."""
    best = 1 << 30
    if "hash" in syntax:
        pos = line.find("#")
        while pos != -1:
            if (pos == 0 or line[pos - 1] in " \t;") and not _in_string(line, pos):
                best = min(best, pos)
                break
            pos = line.find("#", pos + 1)
    if "slash" in syntax:
        pos = line.find("//")
        while pos != -1:
            if (pos == 0 or line[pos - 1] != ":") and not _in_string(line, pos):
                best = min(best, pos)
                break
            pos = line.find("//", pos + 2)
        pos = line.find("/*")
        if pos != -1 and not _in_string(line, pos):
            best = min(best, pos)
    if "dash" in syntax:
        pos = line.find("--")
        if pos != -1 and not _in_string(line, pos):
            best = min(best, pos)
    if "xml" in syntax:
        pos = line.find("<!--")
        if pos != -1:
            best = min(best, pos)
    if "semi" in syntax:
        stripped = line.lstrip()
        if stripped.startswith(";"):
            best = min(best, len(line) - len(stripped))
    return best


_PY_DOC = re.compile(r"^[ \t]*[rRbBuUfF]{0,2}(\"\"\"|''')")


def _block_flags(lines: List[str], syntax: frozenset) -> bytearray:
    """flags[i] == 1 when line i lies wholly inside a block comment/docstring."""
    flags = bytearray(len(lines))
    closer = None
    for i, line in enumerate(lines):
        if closer is not None:
            flags[i] = 1
            if closer in line:
                closer = None
            continue
        if "slash" in syntax:
            pos = line.find("/*")
            if pos != -1 and "*/" not in line[pos + 2:] and not _in_string(line, pos):
                closer = "*/"
                continue
        if "xml" in syntax:
            pos = line.find("<!--")
            if pos != -1 and "-->" not in line[pos + 4:]:
                closer = "-->"
                continue
        if "pydoc" in syntax:
            m = _PY_DOC.match(line)
            if m:
                flags[i] = 1
                if line.count(m.group(1)) % 2 == 1:
                    closer = m.group(1)
    return flags


# ----------------------------------------------------------------------
# Matching
# ----------------------------------------------------------------------

def _is_blob(token: str) -> bool:
    """True for encoded data (hashes, tokens, DER), False for long identifiers.

    Encoded data switches between upper case, lower case and digits on about
    two characters in three. Identifiers switch far less often, even camelCase
    ones full of numbers (TestHandshakeClientECDHERSAChaCha20Poly1305SHA256),
    and they contain whole words, which show up as long lower-case runs.
    """
    upper = lower = digit = switches = 0
    run = longest_lower_run = 0
    prev = ""
    for ch in token:
        if ch.isupper():
            kind = "u"; upper += 1
        elif ch.islower():
            kind = "l"; lower += 1
        elif ch.isdigit():
            kind = "d"; digit += 1
        else:
            continue                      # separators are neutral
        if kind == "l":
            run += 1
            if run > longest_lower_run:
                longest_lower_run = run
        else:
            run = 0
        if prev and kind != prev:
            switches += 1
        prev = kind
    letters = upper + lower + digit
    if not (upper and lower and digit) or letters < 40:
        return False
    rate = switches / (letters - 1)
    return rate >= 0.5 or (rate >= 0.4 and longest_lower_run <= 6)


_LABEL = re.compile(r"[A-Za-z]{2,10}[0-9]{0,4}[-_]")


def _blob_start(token: str) -> int:
    """Offset where encoded data starts in `token`, or -1 if it is not data.

    Usually 0. A short label glued to the payload is kept: in a subresource
    integrity value "sha384-<base64>", "sha384" is worth reading.
    """
    label = _LABEL.match(token)
    if label and _is_blob(token[label.end():]):
        return label.end()
    return 0 if _is_blob(token) else -1


def _mask(text: str) -> str:
    """Blank out base64 payloads while keeping every character offset."""
    def blank_pem(m):
        return m.group(1) + re.sub(r"[^\n]", " ", m.group(2)) + m.group(3)

    def blank_blob(m):
        token = m.group(0)
        start = _blob_start(token)
        return token if start < 0 else token[:start] + " " * (len(token) - start)

    if "-----BEGIN " in text:
        text = _PEM_BODY.sub(blank_pem, text)
    return _BLOB.sub(blank_blob, text)


_PRIVATE_TAIL = re.compile(r"(PRIVATE KEY-----).*")
REDACTED = "[redacted]"


def _redact(line: str) -> str:
    """Remove encoded payloads from a line before it is shown in a report.

    A private key pasted into a JSON string or an environment file sits on
    one line with its PEM header, so the source line itself is sensitive.
    """
    def blob(m):
        token = m.group(0)
        start = _blob_start(token)
        if start >= 0:
            return token[:start] + REDACTED
        # too long to be a name, whatever its shape
        if len(token) >= 60 and any(c.isdigit() for c in token) \
                and any(c.islower() for c in token) and any(c.isupper() for c in token):
            return REDACTED
        return token

    if "PRIVATE KEY-----" in line:
        line = _PRIVATE_TAIL.sub(r"\1 " + REDACTED, line)
    return _BLOB.sub(blob, line)


def _snippet(line: str, col: int, match: str = "") -> str:
    stripped = _redact(line).strip()
    if len(stripped) <= MAX_SNIPPET:
        return stripped
    offset = stripped.find(match) if match else -1
    if offset < 0:
        offset = min(max(col - (len(line) - len(line.lstrip())), 0), len(stripped) - 1)
    start = max(0, offset - MAX_SNIPPET // 2)
    piece = stripped[start:start + MAX_SNIPPET]
    return ("..." if start else "") + piece + ("..." if start + MAX_SNIPPET < len(stripped) else "")


def _fingerprint(path: str, algorithm: str, snippet: str) -> str:
    raw = "\0".join((path.replace(os.sep, "/"), algorithm, " ".join(snippet.split())))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:20]


def _make_finding(rule: Rule, rel: str, line_no: int, col: int, match: str,
                  snippet: str, context: str, mention: bool, policy: str,
                  detail: str = "") -> Finding:
    risk, note = apply_policy(policy, rule.algorithm, match + " " + detail,
                              rule.risk, rule.note)
    return Finding(
        path=rel, line=line_no, col=col + 1, rule_id=rule.id,
        algorithm=rule.algorithm, family=rule.family, use=rule.use,
        quantum=rule.quantum, risk=risk,
        priority=priority_for(rule.quantum, rule.use, risk),
        replace_with=rule.replace_with, match=match, snippet=snippet,
        context=context, mention=mention, detail=detail, note=note,
    )


def scan_text(text: str, rel: str, name: str, policy: str = "nist") -> List[Finding]:
    """Scan one file's text. `rel` is the path used in reports."""
    return _scan_text(text, rel, name, policy)[0]


def _line_starts(text: str) -> List[int]:
    starts = [0]
    pos = text.find("\n")
    while pos != -1:
        starts.append(pos + 1)
        pos = text.find("\n", pos + 1)
    return starts


def _find_hits(text: str, prefilter: bool = True):
    """Run every rule over `text`. Return (hits, line starts or None, capped).

    A hit is (start, end, rule, is_strong). Running forty regexes over every
    byte of every file is slow, so each rule lists plain substrings ("hints")
    that any match must contain. Those are located with str.find, and the
    regex only runs on the lines that hold one. tests/test_rules.py checks
    that this gives exactly the same result as scanning the whole text.
    """
    low = text.lower()
    hits = []
    masked = None

    # str.lower() changes the length of a few Unicode characters; offsets
    # would no longer line up, so fall back to whole-text matching.
    if not prefilter or len(low) != len(text):
        for rule in RULES:
            if not any(hint in low for hint in rule.hints):
                continue
            if masked is None:
                masked = _mask(text)
            for pattern, strong in ((rule.strong, True), (rule.weak, False)):
                if pattern is not None:
                    for m in pattern.finditer(masked):
                        hits.append((m.start(), m.end(), rule, strong))
        return hits, None, False

    starts = None
    size = len(text)
    for rule in RULES:
        wanted = None
        for hint in rule.hints:
            pos = low.find(hint)
            if pos == -1:
                continue
            if starts is None:
                starts = _line_starts(text)
            if wanted is None:
                wanted = set()
            last = len(starts) - 1
            while pos != -1:
                idx = bisect.bisect_right(starts, pos) - 1
                wanted.add(idx)
                if idx >= last:
                    break
                pos = low.find(hint, starts[idx + 1])
        if not wanted:
            continue
        if masked is None:
            masked = _mask(text)
        last = len(starts) - 1
        if len(hits) > MAX_HITS_PER_FILE:
            break
        for idx in sorted(wanted):
            if len(hits) > MAX_HITS_PER_FILE:
                break
            begin = starts[idx]
            end = starts[idx + 1] - 1 if idx < last else size
            if rule.strong is not None:
                for m in rule.strong.finditer(masked, begin, end):
                    hits.append((m.start(), m.end(), rule, True))
            if rule.weak is not None:
                for m in rule.weak.finditer(masked, begin, end):
                    hits.append((m.start(), m.end(), rule, False))
    return hits, starts, len(hits) > MAX_HITS_PER_FILE


def _scan_text(text: str, rel: str, name: str, policy: str, prefilter: bool = True):
    """Return (findings, parsed certificate/key objects, capped) for one file."""
    hits, starts, capped = _find_hits(text, prefilter)

    objects = certs.scan_text(text) if ("-----BEGIN " in text or "AAAA" in text) else []
    if not hits and not objects:
        return [], [], False

    kind, syntax = _file_kind(name)
    lines = text.split("\n")
    if starts is None:
        starts = _line_starts(text)
    flags = _block_flags(lines, syntax) if syntax & {"slash", "xml", "pydoc"} else None

    # Group hits by line, then resolve overlaps longest-first.
    by_line: Dict[int, list] = {}
    for start, end, rule, strong in hits:
        idx = bisect.bisect_right(starts, start) - 1
        by_line.setdefault(idx, []).append((start, end, rule, strong))

    kept_by_line: Dict[int, list] = {}
    has_strong = False
    for idx, group in by_line.items():
        group.sort(key=lambda h: (-(h[1] - h[0]), not h[3], h[0]))
        kept = []
        for h in group:
            if any(k[0] < h[1] and h[0] < k[1] for k in kept):
                continue
            kept.append(h)
            has_strong = has_strong or h[3]
        kept_by_line[idx] = kept

    # Weak tokens ("rsa", "DES", "P-256") need corroboration. A strong match or
    # a parsed key anywhere in the file is enough. Failing that, general crypto
    # vocabulary must be close by: within two lines in code (in Go networking
    # code `rsa` is a raw socket address), anywhere in a config file or a doc.
    crypto_file = has_strong or bool(objects)
    vocabulary_file = None

    def weak_allowed(idx: int) -> bool:
        nonlocal vocabulary_file
        if crypto_file:
            return True
        if kind == "code":
            near = "\n".join(lines[max(0, idx - 2):idx + 3]).lower()
            return bool(_CONTEXT.search(near))
        if vocabulary_file is None:
            vocabulary_file = bool(_CONTEXT.search(text.lower()))
        return vocabulary_file

    findings: List[Finding] = []
    for idx in sorted(kept_by_line):
        line = lines[idx]
        if IGNORE_MARKER.search(line):
            continue
        best: Dict[str, tuple] = {}
        extra_detail: Dict[str, List[str]] = {}
        for h in kept_by_line[idx]:          # longest first
            if not h[3] and not weak_allowed(idx):
                continue
            algo = h[2].algorithm
            if algo not in best:
                best[algo] = h
            else:                            # same algorithm twice on a line
                other = text[h[0]:h[1]]
                seen = extra_detail.setdefault(algo, [])
                main = text[best[algo][0]:best[algo][1]].lower()
                # keep a second match only if it adds a parameter (curve, size)
                if any(ch.isdigit() for ch in other) and other.lower() not in main \
                        and other not in seen:
                    seen.append(other)
        if not best:
            continue

        # generic rules step aside for specific ones on the same line
        for algo in list(best):
            rule = best[algo][2]
            start, end = best[algo][0], best[algo][1]
            matched = text[start:end]
            winners = [a for a in rule.yields_to if a in best]
            if not any(ch.isdigit() for ch in matched):
                # "elliptic curve" next to Ed25519 adds nothing; "secp384r1"
                # next to X25519 is a second curve and stays its own finding
                winners += [a for a in rule.yields_generic_to if a in best]
            if winners:
                for w in winners:
                    extra_detail.setdefault(w, []).append(matched)
                extra_detail.pop(algo, None)
                del best[algo]

        comment_col = _comment_col(line, syntax) if syntax else 1 << 30
        in_block = bool(flags[idx]) if flags is not None else False
        for algo, (start, end, rule, _strong) in sorted(best.items(), key=lambda kv: kv[1][0]):
            col = start - starts[idx]
            if kind == "doc":
                context, mention = "doc", True
            elif in_block or col >= comment_col:
                context, mention = "comment", True
            elif kind == "config":
                context, mention = "config", False
            else:
                context, mention = "code", False
            findings.append(_make_finding(
                rule, rel, idx + 1, col, text[start:end],
                _snippet(line, col, text[start:end]),
                context, mention, policy,
                detail=", ".join(extra_detail.get(algo, [])),
            ))

    # Parsed certificates and keys replace the pattern hit on their header line.
    for obj in objects:
        rule = RULES_BY_ID[obj.rule_id]
        line = lines[obj.line - 1] if obj.line - 1 < len(lines) else ""
        if IGNORE_MARKER.search(line):
            continue
        context = "certificate" if obj.kind == "certificate" else "key"
        findings = [f for f in findings
                    if not (f.line == obj.line and f.algorithm == rule.algorithm)]
        findings.append(_make_finding(
            rule, rel, obj.line, 0, obj.key_algorithm, _snippet(line, 0),
            context, False, policy, detail=obj.describe(),
        ))
        if obj.weak_signature_hash:
            rule_id = "SHA1-001" if obj.weak_signature_hash == "SHA-1" else "MD5-001"  # pqscan: ignore
            hash_rule = RULES_BY_ID[rule_id]
            findings.append(_make_finding(
                hash_rule, rel, obj.line, 0, obj.signature_algorithm,
                _snippet(line, 0), "certificate", False, policy,
                detail="Certificate signed with " + obj.signature_algorithm,
            ))

    findings.sort(key=lambda f: (f.line, f.col))
    return findings, objects, capped


# ----------------------------------------------------------------------
# Walking
# ----------------------------------------------------------------------

def load_ignore_file(root: str) -> List[str]:
    path = os.path.join(root, IGNORE_FILE_NAME)
    patterns = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.append(line)
    except OSError:
        pass
    return patterns


def _excluded(rel_posix: str, patterns: Iterable[str]) -> bool:
    parts = rel_posix.split("/")
    for pat in patterns:
        p = pat.strip().rstrip("/")
        if not p:
            continue
        if p.startswith("/"):
            p = p[1:]
            if fnmatch.fnmatch(rel_posix, p) or rel_posix.startswith(p + "/"):
                return True
            continue
        if fnmatch.fnmatch(rel_posix, p) or rel_posix.startswith(p + "/"):
            return True
        if "/" not in p and any(fnmatch.fnmatch(part, p) for part in parts):
            return True
    return False


def _looks_generated(head: str) -> bool:
    return GENERATED_MARKER in head or ('"bomFormat"' in head and "CycloneDX" in head)


def scan_path(root: str, policy: str = "nist", excludes: Iterable[str] = (),
              skip_paths: Iterable[str] = (),
              max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
              include_mentions: bool = False,
              skip_tests: bool = False) -> ScanResult:
    """Walk `root` and return every cryptographic finding.

    excludes    glob patterns (also read from .pqscanignore in the root)
    skip_paths  exact files to leave out, e.g. the report being written
    skip_tests  leave out test directories and test files
    """
    started = time.time()
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        raise NotADirectoryError(f"not a directory: {root}")

    patterns = list(excludes) + load_ignore_file(root)
    skip_real = {os.path.realpath(p) for p in skip_paths if p}

    result = ScanResult(root=root, policy=policy, files_scanned=0,
                        files_skipped=0, findings=[],
                        include_mentions=include_mentions)

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and not d.endswith(SKIP_DIR_SUFFIXES)
            and not (skip_tests and d.lower() in TEST_DIRS)
            and not _excluded((rel_dir + "/" + d) if rel_dir else d, patterns)
        )

        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            rel_posix = rel.replace(os.sep, "/")
            lower = name.lower()
            ext = os.path.splitext(lower)[1]

            if _excluded(rel_posix, patterns) or os.path.realpath(full) in skip_real:
                result.files_skipped += 1
                continue
            if skip_tests and is_test_path(rel_posix):
                result.files_skipped += 1
                continue
            if os.path.islink(full):
                # A link inside the tree is scanned at its real path; a link
                # that leaves the tree is none of our business.
                result.files_skipped += 1
                continue
            if ext in KEYSTORE_EXT:
                result.keystores.append(rel_posix)
                result.files_skipped += 1
                continue
            if is_manifest(name):
                result.dependencies.extend(parse_manifest(full, rel_posix))
                result.files_scanned += 1
                continue
            if lower in SKIP_FILES or lower.endswith(SKIP_SUFFIXES) or ext in BINARY_EXT:
                result.files_skipped += 1
                continue

            try:
                size = os.path.getsize(full)
                if size > max_file_bytes:
                    result.oversized.append(rel_posix)
                    result.files_skipped += 1
                    continue
                with open(full, "rb") as fh:
                    raw = fh.read()
            except OSError:
                result.files_skipped += 1
                continue

            if b"\0" in raw[:8192]:
                obj = certs.scan_der(raw) if ext in DER_EXT else None
                if obj is None:
                    result.files_skipped += 1
                    continue
                rule = RULES_BY_ID[obj.rule_id]
                file_findings = [_make_finding(
                    rule, rel_posix, 1, 0, obj.key_algorithm, "(binary DER certificate)",
                    "certificate", False, policy, detail=obj.describe())]
                objects = [obj]
                capped = False
            else:
                text = raw.decode("utf-8", "ignore")
                head = text[:2048]
                if _looks_generated(head) or IGNORE_FILE_MARKER.search(head):
                    result.files_skipped += 1
                    continue
                if "\r" in text:
                    text = text.replace("\r\n", "\n").replace("\r", "\n")
                if "BEGIN ENCRYPTED PRIVATE KEY" in text:
                    # PKCS#8 encrypted: the algorithm is inside the ciphertext
                    result.keystores.append(rel_posix)
                file_findings, objects, capped = _scan_text(text, rel_posix, name, policy)

            result.files_scanned += 1
            if capped and len(file_findings) <= MAX_FINDINGS_PER_FILE:
                result.truncated.append(rel_posix)
            if len(file_findings) > MAX_FINDINGS_PER_FILE:
                result.truncated.append(rel_posix)
                file_findings.sort(key=lambda f: f.sort_key())
                file_findings = file_findings[:MAX_FINDINGS_PER_FILE]
            result.findings.extend(file_findings)
            for obj in objects:
                if obj.kind != "certificate":
                    continue
                result.certificates.append({
                    "path": rel_posix, "line": obj.line,
                    "subject": obj.subject, "issuer": obj.issuer,
                    "key_algorithm": obj.key_algorithm, "key_bits": obj.key_bits,
                    "signature_algorithm": obj.signature_algorithm,
                    "not_before": obj.not_before, "not_after": obj.not_after,
                    "self_signed": obj.self_signed,
                    "quantum_safe": RULES_BY_ID[obj.rule_id].quantum == "safe",
                })

    # Stable fingerprints: identical lines in one file get a running index.
    seen: Dict[str, int] = {}
    for f in result.findings:
        base = _fingerprint(f.path, f.algorithm, f.snippet)
        seen[base] = seen.get(base, 0) + 1
        f.fingerprint = base if seen[base] == 1 else "%s-%d" % (base, seen[base])

    result.findings.sort(key=lambda f: f.sort_key())
    result.dependencies.sort(key=lambda d: (d.path, d.library.lower()))
    result.elapsed = time.time() - started
    return result
