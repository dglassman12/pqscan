<!-- pqscan-generated: this file is skipped by later scans -->
# Cryptographic Inventory Report

**Target:** `examples`  
**Generated:** 2026-11-15 20:22  
**Policy:** nist: FIPS 203/204/205 and NIST IR 8547  
**Files scanned:** 12  
**Findings:** 67  
**Certificates:** 4  
**Crypto libraries:** 6

## Summary

The scan found **30 uses of quantum-vulnerable public-key cryptography** across 8 files, plus 19 other items that need attention.
**14%** of public-key usage (5 of 35) is already post-quantum or hybrid.

| Risk | Count | Meaning |
|---|---:|---|
| critical | 30 | Quantum-vulnerable public-key crypto |
| high | 13 | Classically weak, replace regardless |
| low | 5 | Approved, below strictest profile |
| info | 1 | Needs a human to confirm |
| safe | 18 | Post-quantum safe |

### Deadlines

| Milestone | Date | Time left |
|---|---|---|
| Deprecated by NIST | after 2030-12-31 | 4.1 years |
| Disallowed by NIST | after 2035-12-31 | 9.1 years |

Dates are from NIST IR 8547 and apply to quantum-vulnerable public-key algorithms (the critical findings). Check the current text before planning against them.

## What to fix first

Ordered by threat, not by count.

### 1. Key establishment and encryption (22 findings)

Exposed to harvest-now-decrypt-later: traffic captured today can be decrypted later. Move these first, starting with anything that protects data with a long confidentiality lifetime.

| Algorithm | Count | Replace with |
|---|---:|---|
| RSA | 11 | ML-KEM (FIPS 203) for key establishment and encryption; ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) for signatures |
| ECDH | 4 | ML-KEM (FIPS 203); a hybrid such as X25519MLKEM768 during transition |
| Diffie-Hellman (finite field) | 3 | ML-KEM (FIPS 203); a hybrid such as X25519MLKEM768 during transition |
| X25519 / X448 | 2 | ML-KEM (FIPS 203); a hybrid such as X25519MLKEM768 during transition |
| Elliptic curve (scheme not stated) | 2 | ML-KEM (FIPS 203) for key agreement; ML-DSA (FIPS 204) for signatures |

### 2. Signatures and certificates (8 findings)

Forgery needs a quantum computer at attack time, so there is more runway. Start with long-lived roots of trust: code signing, firmware, CA certificates.

| Algorithm | Count | Replace with |
|---|---:|---|
| ECDSA | 5 | ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) |
| RSA | 2 | ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) |
| EdDSA | 1 | ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) |

### 3. Classically weak primitives (13 findings)

Already broken or deprecated without any quantum computer. Usually the cheapest fixes on the list.

| Algorithm | Count | Replace with |
|---|---:|---|
| SHA-1 | 7 | SHA-256 or stronger (SHA-384 for CNSA 2.0) |
| TLS 1.0 / 1.1 | 2 | TLS 1.3 (the only version with post-quantum hybrid key exchange) |
| 3DES | 2 | AES-256 (GCM) or ChaCha20-Poly1305 |
| RC4 | 1 | AES-256 (GCM) or ChaCha20-Poly1305 |
| MD5 | 1 | SHA-256 or stronger (SHA-384 for CNSA 2.0) |

### 4. Policy and hardening (6 findings)

Approved today but below the selected policy, or a parameter that needs a human to confirm.

| Algorithm | Count | Replace with |
|---|---:|---|
| AES-128 | 5 | AES-256 where policy requires it |
| AES (key size not stated) | 1 | Confirm the key length; use 256-bit keys |

## Where it lives

Findings by top-level directory. Priority 1 is key establishment and encryption, 2 is signatures, 3 is classically weak, 4 is policy.

| Area | P1 | P2 | P3 | P4 | Total |
|---|---:|---:|---:|---:|---:|
| `deploy` | 9 | 3 | 5 | 1 | 18 |
| `(top level)` | 8 | 1 | 3 | 4 | 16 |
| `services` | 5 | 4 | 5 | 1 | 15 |

| File | Critical | High | Total |
|---|---:|---:|---:|
| `vulnerable_app.py` | 9 | 3 | 16 |
| `services/gateway/tls.go` | 7 | 3 | 11 |
| `deploy/sshd_config` | 5 | 1 | 6 |
| `deploy/nginx.conf` | 4 | 3 | 8 |
| `services/payments/TokenSigner.java` | 2 | 2 | 4 |
| `deploy/certs/legacy-root.example.test.crt` | 1 | 1 | 2 |
| `deploy/certs/api.example.test.crt` | 1 | 0 | 1 |
| `deploy/certs/gateway.example.test.crt` | 1 | 0 | 1 |

## Certificates

Parsed from PEM and DER files. A certificate that outlives a deadline above has to be reissued with a post-quantum key before then.

| File | Subject | Key | Signature | Expires |
|---|---|---|---|---|
| `deploy/certs/api.example.test.crt` | CN=api.example.test | RSA-2048 | sha256WithRSAEncryption | 2034-04-08 |
| `deploy/certs/gateway.example.test.crt` | CN=gateway.example.test | EC P-256 | ecdsa-with-SHA256 | 2029-05-04 |
| `deploy/certs/legacy-root.example.test.crt` | CN=Legacy Root CA (test fixture) | RSA-2048 | sha1WithRSAEncryption | 2036-09-24 |
| `pq/pq.example.test.crt` | CN=pq.example.test | ML-DSA-65 | ML-DSA-65 | 2036-10-29 |

## Cryptographic dependencies

Libraries that implement cryptography. A dependency is not a vulnerability, but each one is a place where quantum-vulnerable algorithms may be in use even if your own code never names them.

| Ecosystem | Library | Version | Manifest | Note | Post-quantum path |
|---|---|---|---|---|---|
| pypi | `cryptography` | ==41.0.7 | `requirements.txt` | Python crypto bindings: RSA, ECC, AES, hashes | ML-KEM and ML-DSA from version 48 |
| pypi | `paramiko` | ==3.4.0 | `requirements.txt` | SSH implementation: RSA / ECDSA / Ed25519 keys |  |
| pypi | `pyjwt` | ==2.8.0 | `requirements.txt` | JOSE / JWT: usually RSA or ECDSA signed |  |
| npm | `@noble/post-quantum` | ^0.2.0 | `web/package.json` | Post-quantum algorithms | Already a post-quantum library |
| npm | `jsonwebtoken` | ^9.0.2 | `web/package.json` | JOSE / JWT: usually RSA or ECDSA signed |  |
| npm | `node-forge` | 1.3.1 | `web/package.json` | TLS, RSA and X.509 in JavaScript |  |

## Findings (25 of 49)

| Risk | Algorithm | Location | Context | Detail |
|---|---|---|---|---|
| critical | RSA | `deploy/certs/api.example.test.crt:1` | certificate | `X.509 certificate, CN=api.example.test, RSA-2048, signed with sha256WithRSAEncryption, ...` |
| critical | RSA | `deploy/certs/legacy-root.example.test.crt:1` | certificate | `X.509 certificate, CN=Legacy Root CA (test fixture), RSA-2048, signed with sha1WithRSAE...` |
| critical | ECDH | `deploy/nginx.conf:8` | config | `ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:RC4-SHA;` |
| critical | RSA | `deploy/nginx.conf:8` | config | `ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:RC4-SHA;` |
| critical | Diffie-Hellman (finite field) | `deploy/nginx.conf:8` | config | `ssl_ciphers         ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-SHA:RC4-SHA;` |
| critical | Diffie-Hellman (finite field) | `deploy/nginx.conf:9` | config | `ssl_dhparam         /etc/nginx/dhparam.pem;` |
| critical | RSA | `deploy/sshd_config:2` | config | `HostKey /etc/ssh/ssh_host_rsa_key` |
| critical | X25519 / X448 | `deploy/sshd_config:4` | config | `KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,diffie-hellman-group14-sha1` |
| critical | Diffie-Hellman (finite field) | `deploy/sshd_config:4` | config | `KexAlgorithms mlkem768x25519-sha256,curve25519-sha256,diffie-hellman-group14-sha1` |
| critical | ECDH | `services/gateway/tls.go:19` | code | `tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,` |
| critical | RSA | `services/gateway/tls.go:19` | code | `tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,` |
| critical | RSA | `services/gateway/tls.go:20` | code | `tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,` |
| critical | X25519 / X448 | `services/gateway/tls.go:22` | code | `CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},` |
| critical | Elliptic curve (scheme not stated) | `services/payments/TokenSigner.java:22` | code | `KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");` |
| critical | RSA | `vulnerable_app.py:11` | code | `from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding` |
| critical | RSA | `vulnerable_app.py:18` | code | `return rsa.generate_private_key(public_exponent=65537, key_size=2048)` |
| critical | Elliptic curve (scheme not stated) | `vulnerable_app.py:23` | code | `return ec.generate_private_key(ec.SECP256R1())` |
| critical | RSA | `vulnerable_app.py:29` | code | `return key.sign(payload, padding.PKCS1v15(), hashes.SHA256())` |
| critical | ECDH | `vulnerable_app.py:69` | code | `ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")` |
| critical | RSA | `vulnerable_app.py:69` | code | `ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")` |
| critical | RSA | `vulnerable_app.py:76` | code | `"signing_algorithm": "RSA-2048",` |
| critical | ECDH | `vulnerable_app.py:79` | code | `"kex": "ECDH",` |
| critical | ECDSA | `deploy/certs/gateway.example.test.crt:1` | certificate | `X.509 certificate, CN=gateway.example.test, EC P-256, signed with ecdsa-with-SHA256, ex...` |
| critical | RSA | `deploy/sshd_config:3` | config | `HostKeyAlgorithms ssh-rsa,rsa-sha2-512,ssh-ed25519` |
| critical | EdDSA | `deploy/sshd_config:3` | config | `HostKeyAlgorithms ssh-rsa,rsa-sha2-512,ssh-ed25519` |

*24 more findings not shown. The HTML report, CBOM and JSON output have the full set.*

## Already post-quantum safe

Recorded for inventory completeness. No action needed.

| Algorithm | Count |
|---|---:|
| SHA-256 | 6 |
| AES-256 | 4 |
| Hybrid PQ key exchange | 2 |
| ML-DSA | 2 |
| ChaCha20 | 1 |
| ML-KEM | 1 |
| SHA-384 | 1 |
| SHA-512 | 1 |

## Not covered

- 12 matchs in comments and documentation were left out of the counts. Run with `--include-mentions` to count them.

---

Generated by pqscan v0.3.0. Static analysis only: it finds names in source, config, certificates and manifests, not runtime behaviour. Review the findings before treating this as a complete inventory.
