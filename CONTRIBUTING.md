# Contributing to ChaosCrypt-Hybrid

First of all, thank you for considering a contribution to ChaosCrypt-Hybrid. This project is a
research-grade hybrid encryption engine that combines a Lorenz-attractor chaos layer, ML-KEM-768
(NIST FIPS 203), and AES-256-GCM, and it grows through the time and expertise of contributors
like you.

Contributions of all kinds are welcome: bug reports, test coverage, documentation, threat-model
improvements, performance work, and cryptographic review. This guide explains how to get
involved and what is expected from contributions.

---

## Code of Conduct

Be respectful, be constructive, and be welcoming. Harassment, discrimination, personal attacks,
and dismissive behavior are not tolerated in issues, pull requests, or any other project space.
Maintainers may edit, remove, or reject contributions that violate these standards. If you
experience or witness unacceptable behavior, report it to uslumurat405@gmail.com. This project
follows the spirit of the [Contributor Covenant](https://www.contributor-covenant.org/).

---

## How to Contribute

### Reporting Bugs

Before opening an issue, please search the existing issues (open and closed) to avoid
duplicates.

Open a new issue at: https://github.com/uslumurat405-oss/chaoscrypt-hybrid/issues

A good bug report includes:

- A clear, descriptive title and a concise description of the problem
- Your environment: operating system, Python version, and ChaosCrypt version (e.g., v0.3.0)
- A minimal, reproducible example (code snippet or script)
- Expected behavior vs. actual behavior
- The full traceback or error output, if applicable
- Whether the issue is intermittent or reproducible

> **Security vulnerabilities must not be reported in public issues.** Please follow the private
> disclosure process described in [SECURITY.md](SECURITY.md) (email-based, 48-hour
> acknowledgment).

### Suggesting Enhancements

Enhancement proposals are welcome. Open an issue and describe:

- The problem or limitation your idea addresses
- Your proposed solution and how it would be used
- Alternatives you considered
- Any impact on security, timing behavior, or benchmark performance

Before proposing new features, check the Roadmap section of the README — items such as a formal
security proof, an independent audit, AES-NI hardware acceleration, and multi-threading support
are already tracked.

### Pull Request Workflow

1. **Fork** the repository on GitHub:
   https://github.com/uslumurat405-oss/chaoscrypt-hybrid

2. **Clone** your fork and add the upstream repository:

   ```bash
   git clone https://github.com/<your-username>/chaoscrypt-hybrid.git
   cd chaoscrypt-hybrid
   git remote add upstream https://github.com/uslumurat405-oss/chaoscrypt-hybrid.git
   ```

3. **Create a branch** from `main` with a descriptive name:

   ```bash
   git checkout -b feature/short-description
   ```

   Use prefixes such as `feature/`, `fix/`, `docs/`, or `tests/` to indicate the change type.

4. **Make your changes** and add or update tests as required (see Coding Standards). Keep the
   changes focused: one logical change per pull request.

5. **Test** locally — the full suite must pass before you open a pull request:

   ```bash
   python -m pytest tests/ -v
   ```

   If your change touches comparisons, decryption, or decapsulation, also run:

   ```bash
   python -m pytest tests/test_timing_attacks.py -v
   ```

6. **Commit** with a clear message in the imperative mood, for example
   `Add regression test for GCM tag verification`. Reference related issues where applicable
   (e.g., `Fixes #12`).

7. **Push** the branch to your fork:

   ```bash
   git push origin feature/short-description
   ```

8. **Open a pull request** against `main` on the upstream repository. Include:
   - What the change does and why
   - The related issue number, if any
   - Test evidence (command output summary)
   - Security implications, especially for changes on secret-dependent paths

9. **Respond to review feedback.** Maintainers may request timing-test evidence, benchmark
   results, or design changes. Please keep the discussion constructive and be patient — this is
   a research project maintained on a best-effort basis.

---

## Development Setup

**Prerequisites:** Python 3.10 or newer and Git. The project is currently developed and tested
with Python 3.13 on Windows, but it runs on macOS and Linux as well.

```bash
# 1. Clone the repository
git clone https://github.com/uslumurat405-oss/chaoscrypt-hybrid.git
cd chaoscrypt-hybrid

# 2. Create a virtual environment
python -m venv venv
```

Activate the environment:

- **Windows (PowerShell):** `venv\Scripts\Activate.ps1`
- **Windows (cmd):** `venv\Scripts\activate.bat`
- **macOS / Linux:** `source venv/bin/activate`

```bash
# 3. Install dependencies
pip install -r requirements.txt
```

Verify your setup by running the test suite:

```bash
python -m pytest tests/ -v
```

- Full suite: `python -m pytest tests/ -v` (36 tests)
- Timing side-channel tests: `python -m pytest tests/test_timing_attacks.py -v`
- Benchmarks (informational): `python -m pytest tests/test_benchmark.py -v -s`

---

## Coding Standards

- **PEP 8** is the reference style: 4-space indentation, `snake_case` for functions and
  variables, `UPPER_SNAKE_CASE` for constants, and readable line lengths.
- **Type hints** are expected on public function signatures (the project uses modern union
  syntax such as `bytes | None`).
- **Docstrings** are required for every public module, class, and function. Describe behavior,
  parameters, return values, and any security-relevant guarantees (intentionally non-constant
  behavior must be documented as such).
- **Tests are required.** New functionality must include unit tests; bug fixes must include a
  regression test that fails before the fix and passes after it. Tests live in `tests/` and are
  named `test_<module>.py`.
- **Dependencies.** Avoid adding new third-party dependencies. If a new dependency is
  unavoidable, justify it in the pull request and add a compatible version range to
  `requirements.txt`.
- **Commits.** Use clear, imperative commit messages (e.g., `Fix nonce reuse check in hybrid
  cipher`). Group related changes into a single commit and keep unrelated changes separate.
- **Structure.** Cryptographic primitives and the hybrid flow live in `src/crypto_engine.py`;
  keep new code aligned with the existing module layout and naming conventions.

---

## Security Considerations

ChaosCrypt-Hybrid is cryptographic software. Every contributor is expected to preserve its
security properties:

- **Constant-time operations.** All comparisons involving secret material (GCM authentication
  tags, ML-KEM shared secrets, derived keys, version bytes) must go through
  `constant_time_equal()`, which wraps `hmac.compare_digest`. Never compare secrets with `==`,
  `in`, or other short-circuiting operators.
- **No timing leaks.** Avoid secret-dependent branching, early exits, or data-dependent
  indexing on any path that processes key material. Preserve the calibrated equal-work
  verification path for GCM tag checks in `hybrid_decrypt`.
- **Timing tests must keep passing.** Any change touching comparisons, decryption, or
  decapsulation must keep `tests/test_timing_attacks.py` green. Follow the existing measurement
  methodology (interleaved buffer allocation, windowed batch measurement) when adding new
  timing tests.
- **NIST compliance.** ML-KEM-768 is implemented per **NIST FIPS 203** via `pqcrypto`
  (PQClean-derived code). Do not alter parameter sets, reimplement decapsulation in Python, or
  wrap the primitive in ways that change its security contract. Do not weaken the final key
  derivation `SHA3-256(ML-KEM shared secret || chaos key)`.
- **Entropy sources.** The OS CSPRNG (`secrets.token_bytes`) is the only entropy source for key
  material; the Lorenz-attractor output is an entropy mixer layered on top of it, never a
  standalone security primitive.
- **Do not log secrets.** No plaintext, keys, shared secrets, or intermediate chaos state in
  logs, exceptions, or debug output.
- **Coordinated disclosure.** Never disclose a suspected vulnerability in a public issue or pull
  request. Follow [SECURITY.md](SECURITY.md).

---

## Contact

- **Email:** uslumurat405@gmail.com
- **Issues and pull requests:** https://github.com/uslumurat405-oss/chaoscrypt-hybrid/issues
- **Maintainer:** Murat Uslu ([@uslumurat405-oss](https://github.com/uslumurat405-oss))

Thank you for helping make ChaosCrypt-Hybrid better and safer. Every report, review, and line of
documentation counts.
