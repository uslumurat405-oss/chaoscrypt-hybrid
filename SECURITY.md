# Security Policy

**Project:** ChaosCrypt-Hybrid
**Document version:** 1.0
**Last updated:** 2026-09-24

ChaosCrypt-Hybrid is a research-grade hybrid encryption engine that combines a Lorenz-attractor
chaos layer, ML-KEM-768 key encapsulation (NIST FIPS 203), and AES-256-GCM authenticated
encryption. This document defines the project's security policy, the responsible vulnerability
disclosure process, recommended practices for integrators, and the known limitations of the
current implementation.

This policy follows the spirit of NIST SP 800-218 (Secure Software Development Framework, SSDF)
and references NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism Standard) for the
post-quantum component.

---

## 1. Security Policy

### Supported Versions

Security fixes are provided only for the latest released version. Older versions are not
maintained.

| Version | Supported | Notes |
|-----------------|-----------|--------------------------------------------------------|
| v0.3.0 | Yes | Current release. All security fixes are issued here. |
| v0.2.0 and older | No | Please upgrade to v0.3.0 before reporting an issue. |

### Scope

In scope:

- `src/crypto_engine.py` — hybrid encryption/decryption, ML-KEM wrappers, key derivation
- `src/chaotic_csprng.py`, `src/chaos_engine.py` — chaos-based key material generation
- `src/hybrid_cipher.py` — authenticated cipher framing and version handling
- `src/crypto_engine.constant_time_equal()` — constant-time comparison utilities

Out of scope:

- Vulnerabilities in third-party dependencies (`pqcrypto`, `pycryptodome`, `cryptography`,
  `numpy`). Report these upstream; please notify us as well so we can pin or upgrade.
- Issues that require a compromised operating system, a compromised OS CSPRNG, or physical
  access to the host.
- Denial of service through deliberately wasteful use of the public API on untrusted input
  (see Section 4, Known Limitations).

---

## 2. Reporting a Vulnerability

We welcome reports from security researchers and users. Please practice responsible
disclosure: **do not open a public GitHub issue for a suspected vulnerability** until a fix
has been released and coordinated disclosure is agreed.

### How to report

Send an email to:

**uslumurat405@gmail.com**

with the subject line: `[SECURITY] ChaosCrypt-Hybrid — <short description>`

Please include as much of the following as possible:

- A clear description of the vulnerability and the affected component
- The affected version (e.g., v0.3.0) and environment (OS, Python version)
- Step-by-step reproduction instructions or a proof-of-concept script
- Your assessment of impact (confidentiality, integrity, availability)
- Any suggested remediation, if available
- Whether and when you intend to publish your findings

Do not include live secrets, private keys, or personal data in the report. If your
proof-of-concept requires sensitive material, describe the procedure first and we will agree
on a secure exchange method.

### What to expect

| Stage | Target time |
|-------------------------------|--------------------------------------------|
| Acknowledgment of your report | Within **48 hours** |
| Initial triage and assessment | Within 5 business days of acknowledgment |
| Status update | At least every 7 days while a fix is in progress |
| Fix and coordinated disclosure | As soon as practicable, based on severity |

If you do not receive an acknowledgment within 48 hours, please resend your message and
mention the original subject line.

### Coordinated disclosure

- We will work with you to validate the issue, determine severity, and prepare a fix.
- A GitHub Security Advisory and a `CHANGELOG.md` entry will be published together with the
  fix, crediting the reporter unless anonymity is requested.
- We ask that you give us a reasonable window to release a fix before any public disclosure.
  In return, we will not take legal action against researchers who act in good faith under
  this policy.

---

## 3. Security Best Practices

The following practices apply when developing, auditing, or integrating this library.

### 3.1 Constant-time operations

- All comparisons involving secret material (GCM authentication tags, ML-KEM shared secrets,
  derived keys, version bytes in `hybrid_cipher.py`) must go through
  `constant_time_equal()`, which wraps `hmac.compare_digest`.
- Never compare secrets with `==`, `in`, or other short-circuiting operators; comparison time
  must not depend on where the first differing byte occurs.
- ML-KEM decapsulation relies on the constant-time implicit-rejection path provided by
  `pqcrypto` (PQClean-derived code). Keep this dependency current and do not reimplement the
  decapsulation logic in Python.

### 3.2 Timing attack resistance

- Timing behavior is treated as part of the security contract. Before changing code on any
  secret-dependent path, run `tests/test_timing_attacks.py` and verify that comparisons and
  decapsulation remain statistically indistinguishable under the project's measurement
  methodology.
- Avoid secret-dependent branching, early exits, or lookups in new code paths.
- The test suite uses interleaved buffer allocation and windowed batch measurement to
  mitigate cache bias; keep this methodology when adding new timing tests.

### 3.3 Cryptographic standards compliance

- ML-KEM-768 is implemented per **NIST FIPS 203** via the `pqcrypto` library. Do not alter
  parameter sets or wrap the primitive in a way that changes its security contract.
- AES-256-GCM provides confidentiality and integrity for message payloads; the final key is
  derived as `SHA3-256(ML-KEM shared secret || chaos key)`. Do not weaken or reorder this
  derivation.
- Key material must originate from the OS CSPRNG (`secrets.token_bytes`). The Lorenz-attractor
  output is an entropy mixer only; it must never be used as the sole entropy source (per NIST
  SP 800-90A/B expectations for DRBGs).
- Never reuse a (key, nonce) pair with AES-256-GCM. Nonces are generated internally; do not
  override or reuse them.
- Follow NIST SP 800-57 key-management guidance for key lifetimes and separation of duties in
  production deployments.

### 3.4 Operational hygiene

- Verify dependency pins (`requirements.txt`) and upgrade ML-KEM/AES providers promptly when
  security advisories are published for them.
- Run with least privilege; do not run the library with privileges beyond what the
  application requires.
- Do not log plaintext, keys, shared secrets, or intermediate chaos state.
- See `THREAT_MODEL.md` (STRIDE) for the current attack-surface inventory and risk ratings.

### 3.5 Deployment suitability

This library is a research prototype with basic side-channel protection. Unit tests passing is
not a security proof. A formal, independent cryptographic audit is recommended before any
production use that protects real assets.

---

## 4. Known Limitations

The following limitations are inherent to the current implementation. Integrators must
understand and account for them.

### 4.1 Python runtime limitations

- **GIL and scheduling.** The Global Interpreter Lock does not provide constant-time
  execution. Interpreter-level scheduling, thread preemption, and bytecode dispatch introduce
  timing variability. Constant-time code in this project means the *cryptographic logic* does
  not branch on secrets; it cannot guarantee constant wall-clock time at the interpreter
  level.
- **Garbage collection.** CPython's reference counting and cyclic GC can pause execution and
  free buffers at times correlated with allocation patterns. Allocation/deallocation timing
  may leak information about the size and lifetime of secret buffers. Secrets should be held
  in as few objects as possible and for as short a time as possible.
- **Object identity and copies.** Python may transparently copy or intern bytes objects;
  secret material may exist in memory longer than intended. There is no guaranteed memory
  zeroization for immutable `bytes` objects.

### 4.2 Algorithmic limitations

- **Lorenz path is not constant-time.** The pure-Python/NumPy Euler iteration
  (10,000 steps, `float64`) is not constant-time and is treated as an entropy mixer layered
  on top of the OS CSPRNG and ML-KEM shared secret, not as a standalone cryptographic
  primitive.
- **PyCryptodome GCM verification path.** Due to a PyCryptodome API restriction on the
  decrypt path, tag verification recomputes the tag over recovered plaintext to equalize work
  between success and failure paths. This is calibrated and covered by timing tests, but it is
  a workaround around the library, not a hardware-level constant-time guarantee.
- **Native extension boundary.** `pqcrypto` and PyCryptodome execute in native code. Their
  constant-time properties depend on the upstream C implementations and compilation; the
  Python layer cannot verify or enforce them.

### 4.3 Protocol limitations

- No sender authentication or non-repudiation (no signature layer; ML-DSA is a roadmap item).
- Public-key distribution and trust are not addressed by the library (key substitution is
  possible without an out-of-band trust anchor).
- No replay protection, rate limiting, or message-size limits; applications must add these.

### 4.4 Assurance status

- No formal verification and no independent third-party audit to date.
- Unit tests (including timing tests) demonstrate behaviors, not absence of vulnerabilities.
- Side-channel evaluation methods such as TVLA / dudect are on the roadmap.

---

## 5. Contact Information

For all security-related matters:

- **Security contact (email):** uslumurat405@gmail.com
- **GitHub:** [@uslumurat405-oss](https://github.com/uslumurat405-oss)
- **Project repository:** https://github.com/uslumurat405-oss (ChaosCrypt-Hybrid)

Please use the subject prefix `[SECURITY]` for vulnerability reports so they are triaged with
priority. General bugs and feature requests should go through the public issue tracker
instead.

We appreciate the work of security researchers and will credit reported issues in the
release notes and advisory, with your permission.
