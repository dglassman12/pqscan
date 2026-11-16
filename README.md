# pqscan

A cryptographic inventory scanner for post-quantum readiness.

`pqscan` walks a codebase and finds the cryptography in it: in source code,
configuration, certificates, keys and dependency manifests. It classifies each
finding by quantum risk, ranks what to migrate first, and writes the result in
the formats that people and pipelines already use.

No dependencies outside the Python 3.9+ standard library.

## Why

Regulators are beginning to require financial institutions to maintain a
comprehensive inventory of cryptographic assets (algorithms, key lengths,
protocols, and the systems they support) before any migration can be planned.
Most organizations cannot produce that inventory today.

You cannot migrate what you cannot enumerate.

## Quick start

```bash
git clone https://github.com/<you>/pqscan
cd pqscan
pip install .            # gives you the `pqscan` command
pqscan ./my-repo
```

Or run it without installing: `python3 -m pqscan ./my-repo`.

```bash
pqscan . --html report.html                 # interactive report, one file
pqscan . -o report.md --cbom cbom.json      # Markdown report and CycloneDX CBOM
pqscan . --sarif pqscan.sarif               # for GitHub code scanning
pqscan . --policy cnsa2                     # rate against CNSA 2.0 instead of NIST
pqscan . --skip-tests --exclude 'third_party/*'
```

Try it on the bundled example project:

```
$ pqscan examples
Scanned 12 files in 0.0s (0 skipped), policy: nist

30 quantum-vulnerable usages in 8 files
Public-key crypto migrated to post-quantum: 14% (5 of 35)

  critical      30  Quantum-vulnerable public-key crypto
  high          13  Classically weak, replace regardless
  low            5  Approved, below strictest profile
  info           1  Needs a human to confirm
  safe          18  Post-quantum safe

NIST IR 8547: quantum-vulnerable public-key crypto is deprecated after 2030 (4.1 years left), disallowed after 2035 (9.1 years left)

Fix first
  1. Key establishment and encryption         22
  2. Signatures and certificates               8
  3. Classically weak primitives              13
  4. Policy and hardening                      6

Certificates: 4
  deploy/certs/api.example.test.crt: CN=api.example.test, RSA-2048, expires 2034-04-08
  deploy/certs/gateway.example.test.crt: CN=gateway.example.test, EC P-256, expires 2029-05-04
  ...
```

The reports generated from that scan are in [`samples/`](samples/).

## What you get

| Output | Flag | For |
|---|---|---|
| Terminal summary | (default) | A quick read: counts, priorities, hotspots |
| HTML report | `--html FILE` | One self-contained file to filter, search and share. Shows certificate expiry dates against the NIST deadlines |
| Markdown report | `-o FILE` | Tickets, wikis, pull request comments |
| CycloneDX 1.6 CBOM | `--cbom FILE` | Governance and asset-inventory pipelines. Validates against the official schema |
| SARIF 2.1.0 | `--sarif FILE` | GitHub code scanning, GitLab, Azure DevOps, IDEs |
| JSON | `--json FILE` | Your own tooling. Every finding with all its fields |
| SVG badge | `--badge FILE` | A README badge showing the share already migrated |

## What it detects

| Risk | What | Examples |
|---|---|---|
| critical | Public-key algorithms broken by Shor's algorithm | RSA, ECDSA, ECDH, X25519, Ed25519, DH, DSA, ElGamal |
| high | Classically weak; replace regardless of quantum | MD5, SHA-1, DES, 3DES, RC4, TLS 1.0/1.1, SSL 3 |
| medium | Legacy | Blowfish |
| low | Approved by NIST, below stricter profiles | AES-128, AES-192 |
| info | Needs a human to confirm a parameter | AES with the key size set at runtime |
| safe | Post-quantum safe; recorded so progress is visible | ML-KEM, ML-DSA, SLH-DSA, hybrids such as X25519MLKEM768, AES-256, SHA-2, SHA-3, ChaCha20 |

`pqscan --list-rules` prints the full rule set.

Beyond names in source code, it also reads:

- **Certificates and keys.** X.509 (PEM and DER), PKCS#1, PKCS#8, SEC1 and
  OpenSSH keys are parsed, so a finding says "RSA-2048 certificate for
  api.example.test, signed with SHA-1, expires 2034", not just "RSA". Key
  bodies and other encoded payloads are redacted from the source lines shown
  in reports.
- **Dependency manifests.** `requirements*.txt`, `pyproject.toml`, `Pipfile`,
  `package.json`, `pom.xml`, `build.gradle`, `go.mod`, `Gemfile`,
  `composer.json` and `Cargo.toml`. Post-quantum libraries are flagged, and
  for common libraries the report says which version added the NIST algorithms.

### What to fix first

Findings are ordered by threat, not by count:

1. **Key establishment and encryption.** Traffic recorded today can be
   decrypted once a quantum computer exists ("harvest now, decrypt later").
2. **Signatures and certificates.** Forgery needs a quantum computer at the
   time of the attack, so there is more runway.
3. **Classically weak primitives.** Already broken; usually cheap to fix.
4. **Policy and hardening.** Approved today but below the selected policy.

The deadline dates in the reports come from NIST IR 8547 (quantum-vulnerable
public-key algorithms deprecated after 2030, disallowed after 2035). They are
set in `pqscan/summary.py`; check the current text before planning against them.

### Policies

`--policy nist` (the default) follows FIPS 203/204/205 and NIST IR 8547.
`--policy cnsa2` is stricter: AES-128/192, SHA-256, ChaCha20 and the smaller
ML-KEM and ML-DSA parameter sets are rated as findings.

## Using it in CI

Adopting a scanner on an existing codebase usually fails on day one, because
there are already hundreds of findings. A baseline avoids that:

```bash
pqscan . --write-baseline .pqscan-baseline.json     # once; commit the file
pqscan . --baseline .pqscan-baseline.json --fail-on critical
```

The second command exits 1 only when a **new** critical finding appears.
Fingerprints are built from the file, the algorithm and the text of the line,
so they survive unrelated edits above a finding.

GitHub Actions, with findings shown inline on pull requests:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install git+https://github.com/<you>/pqscan
- run: pqscan . --sarif pqscan.sarif --baseline .pqscan-baseline.json --fail-on critical
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: pqscan.sarif }
```

A `pre-commit` hook definition is in `.pre-commit-hooks.yaml`.

Exit codes: `0` success, `1` the `--fail-on` threshold was met, `2` bad
arguments or an unreadable path.

### Suppressing and excluding

```python
digest = hashlib.md5(chunk).hexdigest()  # pqscan: ignore   (cache key, not security)
```

- `pqscan: ignore` in a comment suppresses that line.
- `pqscan: ignore-file` near the top of a file skips the file.
- `.pqscanignore` in the scanned directory lists globs to skip, one per line.
- `--exclude GLOB` does the same from the command line; `--skip-tests` leaves
  out test directories and test files.

`node_modules`, `vendor`, virtualenvs, build output, lockfiles, minified files
and binaries are skipped by default. So are pqscan's own reports, which means
you can write them into the directory you scan.

## How detection works

`pqscan` is a static, pattern-based scanner with a few things on top of grep:

- Names are matched across `_`, `-` and camelCase boundaries, so
  `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `SHA256withRSA` and `ML_KEM_768`
  are all understood. One line can yield several findings.
- Overlapping matches are resolved longest-first: `ML-DSA` is never reported
  as `DSA`, and `X25519MLKEM768` is a hybrid, not plain X25519.
- Short ambiguous words (`rsa`, `DES`, `P-256`) only count next to other
  cryptographic vocabulary or in a file with an unambiguous match. "DES
  MOINES" is not a cipher, and `rsa` in Go networking code is a socket address.
- Base64 payloads (hashes, tokens, key bodies) are masked before matching, so
  random data cannot spell an algorithm.
- Matches in comments and documentation are kept as "mentions" and left out of
  the counts unless you pass `--include-mentions`.

## Limitations

This is a static scanner. It finds *identifiers*, not runtime behavior.

- False positives and misses are both possible; a human should review the
  output. A word such as `DSA` a line away from "key" will be reported even
  if it means something else, and a bare `rsa` far from any crypto vocabulary
  will be missed.
- It does not scan compiled binaries, network traffic, HSM configuration or
  encrypted keystores (`.p12`, `.jks`; these are listed as "not covered").
- It cannot detect crypto implemented in-house without recognizable
  identifiers, or algorithm names built at runtime.
- A dependency on a crypto library is reported, but not which of the library's
  algorithms your code actually calls.
- Comment detection is a per-language heuristic, not a parser.

Treat the output as a starting inventory, not a certified one.

## Development

```bash
python3 -m unittest discover -s tests -t .
pip install ".[test]"      # optional: enables the CycloneDX schema test
```

The project scans itself in CI (`pqscan . --fail-on high`); see
`.pqscanignore` for what is excluded and why. Set `PROJECT_URL` in
`pqscan/__init__.py` to have reports link back to your repository.

To add an algorithm, add a rule to `pqscan/rules.py` and a case to
`tests/test_rules.py`.

## Roadmap

- [x] Dependency manifest parsing
- [x] Certificate file parsing for key length and signature algorithm
- [x] Migration sequencing by threat
- [x] CI integration (baselines, SARIF, exit codes)
- [ ] Language-aware AST parsing for the main languages
- [ ] Key sizes from call arguments (`key_size=2048`, `rsa.GenerateKey(r, 2048)`)
- [ ] Java keystores and PKCS#12 with a supplied password
- [ ] Scanning only the files changed in a pull request

## License

MIT
