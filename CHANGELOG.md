# Changelog

## 0.3.0

### Fixed

- **The CBOM now validates against the CycloneDX 1.6 schema.** In 0.2 every
  component failed: `cryptoFunctions` held pqscan's own category names, and
  AES-256 was labelled a public-key primitive. The CBOM is now one component
  per algorithm with each location recorded as an evidence occurrence, plus
  components for certificates, protocol versions and crypto libraries.
- **ML-DSA and SLH-DSA are no longer reported as critical DSA.** Overlapping
  matches are resolved longest-first, so the post-quantum name wins.
- **Reports written into the scanned directory no longer feed the next scan.**
  In 0.2 three runs in a row gave 17, 130 and 768 findings. Output files are
  excluded by path, and every report carries a marker that later scans skip.
- Files over the size limit are listed as skipped instead of being counted as
  scanned. `.env`, `Dockerfile`, `Makefile`, `.html` and extension-less files
  are now read.
- `pyproject.toml` (PEP 621 and Poetry), `composer.json` vendor/package names,
  and PyPI names written with `_` or mixed case are now recognised.
- `--top` rejects negative numbers; pipes and backticks in paths no longer
  break the Markdown tables.

### Changed

- **Detection was rebuilt.** Names are matched across `_`, `-` and camelCase
  boundaries (`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`, `SHA256withRSA`,
  `ML_KEM_768`, `ec.SECP256R1()`), a line can yield several findings, and
  short ambiguous words (`rsa`, `DES`, `P-256`) only count in files that look
  like crypto. Base64 payloads are masked before matching.
- **Comments and documentation are reported separately** as "mentions" and are
  left out of the counts unless `--include-mentions` is given.
- **Risk levels follow NIST more closely.** AES-128 moved from *high* to *low*:
  NIST still approves it, and only stricter profiles such as CNSA 2.0 require
  AES-256 (`--policy cnsa2` rates it *high*). 3DES and DES are now "classically
  weak" rather than "weakened by Grover". SHA-256, SHA-512, SHA-3, ChaCha20
  and AES with no stated key size are now inventoried.
- The default size limit is 5 MB (was 2 MB); `--max-file-size` changes it.
- The raw JSON output has more fields per finding. `also_matched` is gone:
  each algorithm on a line is its own finding.

### Added

- Certificate and key parsing (X.509 PEM/DER, PKCS#1, PKCS#8, SEC1, OpenSSH):
  algorithm, key size, signature hash, subject and expiry, with no dependencies.
- Migration priorities: key establishment first (harvest now, decrypt later),
  then signatures, then classically weak primitives, then policy items.
- Interactive HTML report (`--html`), SARIF 2.1.0 (`--sarif`), SVG badge
  (`--badge`).
- Baselines (`--write-baseline`, `--baseline`) so CI can fail on new findings
  only; `--fail-on LEVEL`.
- `# pqscan: ignore`, `pqscan: ignore-file`, `.pqscanignore`, `--exclude`,
  `--skip-tests`.
- `--policy cnsa2`, `--list-rules`.
- Post-quantum and hybrid algorithms: ML-KEM, ML-DSA, SLH-DSA, FN-DSA, HQC,
  LMS/XMSS, X25519MLKEM768 and friends; post-quantum libraries are flagged, and
  common libraries show the version that added the NIST algorithms.
- Installable: `pip install .` gives a `pqscan` command.
- Private key bodies and other encoded payloads are redacted from the source
  lines shown in reports.
- A test suite (72 tests, standard library only).
