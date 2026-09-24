![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Tests](https://img.shields.io/badge/Tests-36_Passing-brightgreen)
![Security](https://img.shields.io/badge/Security-Timing_Attack_Resistant-orange)
![NIST](https://img.shields.io/badge/NIST-FIPS_203-yellow)
![License](https://img.shields.io/badge/License-MIT-green)

# ChaosCrypt-Hybrid

Lorenz attractor, ML-KEM-768 (FIPS 203) ve AES-256-GCM tabanlı hibrit şifreleme motoru.
...
# ChaosCrypt-Hybrid

Lorenz attractor, ML-KEM-768 (FIPS 203) ve AES-256-GCM tabanlı hibrit şifreleme motoru.

Araştırma prototipi: kaos tabanlı anahtar türetimi, OS CSPRNG ve post-kuantum KEM bir arada kullanılır.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```python
from src.crypto_engine import generate_kyber_keys, hybrid_encrypt, hybrid_decrypt

public_key, private_key = generate_kyber_keys()
packet = hybrid_encrypt(b"secret message", public_key)
plaintext = hybrid_decrypt(packet, private_key)
```

## Benchmarks

Measured with `python -m pytest tests/test_benchmark.py -v -s` (Python 3.13.5, Windows):

| Operation | Avg (ms) | Ops/sec |
|-----------|----------|---------|
| ML-KEM-768 key generation | 0.117 | 8,540 |
| ML-KEM-768 encapsulation | 0.150 | 6,678 |
| ML-KEM-768 decapsulation | 0.136 | 7,345 |
| AES-256-GCM encryption (1MiB) | 2.012 | 497 |
| Lorenz key generation | 102.878 | 9.7 |
| Hybrid encrypt/decrypt cycle | 206.058 | 4.9 |

Rating: **6 Fast / 0 Medium / 0 Slow** — All within acceptable thresholds.

Lorenz key generation (pure-Python, 10,000 iterations) dominates the hybrid cycle cost; ML-KEM-768 and AES-256-GCM are negligible by comparison.

## Testing

- 36 total tests passing (23 original + 13 timing attack tests)
- Timing attack resistance verified
- Cache bias mitigation implemented
- Run tests: `python -m pytest tests/ -v`

## Mimari

```
Plaintext → [Lorenz Key + OS CSPRNG] + [ML-KEM-768 Shared Secret] → AES-256-GCM → Ciphertext
```

## Security Features

- ✅ Constant-Time Operations (Side-channel resistant)
- ✅ Timing Attack Protection (13 comprehensive tests)
- ✅ OS CSPRNG Integration (secrets.token_bytes)
- ✅ ML-KEM-768 (NIST FIPS 203)
- ✅ AES-256-GCM authenticated encryption
- ✅ STRIDE threat model documented (`THREAT_MODEL.md`)

All secret-material comparisons (GCM authentication tags, ML-KEM shared secrets, derived keys) use `hmac.compare_digest` via `constant_time_equal`.

## Examples

A complete, runnable example lives in [`examples/basic_usage.py`](examples/basic_usage.py).

### 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/uslumurat405-oss/chaoscrypt-hybrid.git
cd chaoscrypt-hybrid

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the example
python examples/basic_usage.py
```

### 📋 Expected Output

```text
$ python examples/basic_usage.py
======================================================================
ChaosCrypt-Hybrid - basic usage example
======================================================================

[1] Generating ML-KEM-768 key pair ...
    Public key : 1184 bytes
    Private key: 2400 bytes  (keep this secret)

[2] Encrypting the message ...
    Plaintext        : ChaosCrypt-Hybrid: post-quantum + chaos hybrid encryption demo.
    Ciphertext + tag : 79 bytes
    GCM nonce        : 12 bytes
    ML-KEM ciphertext: 1088 bytes
    Chaos seed       : 32 bytes

[3] Decrypting the packet ...
    Recovered        : ChaosCrypt-Hybrid: post-quantum + chaos hybrid encryption demo.
    Result           : OK - decrypted text matches the original.

[4] Tamper detection check ...
    Tampered packet rejected as expected (AES-GCM authentication failed: tag mismatch).

Done.
```

### 💡 What This Means

- 🔐 **Post-quantum key sizes** — the 1184-byte public key and 2400-byte private key come from ML-KEM-768's lattice-based construction (NIST FIPS 203); they are larger than classical ECC keys because they must resist both classical and quantum attackers.
- ✅ **Tamper detection** — AES-256-GCM authenticates the ciphertext, so flipping a single bit makes the tag check fail: decryption raises an error instead of returning corrupted plaintext.
- ⏱️ **Timing attack resistance** — all secret comparisons run in constant time via `constant_time_equal` (`hmac.compare_digest`), so verification duration does not reveal where bytes match or differ.

## Security Notice

- Research-grade with basic side-channel protection
- Constant-time operations implemented
- Formal audit recommended for production

## Roadmap

- [ ] Formal security proof
- [ ] Professional security audit
- [ ] Hardware acceleration (AES-NI)
- [ ] Multi-threading support

## Changelog

### v0.3.0

Constant-Time Operations + Timing Tests + Benchmarks

- All secret-material comparisons use `hmac.compare_digest` (`constant_time_equal`)
- GCM tag verification in `hybrid_decrypt` is explicitly constant-time
- 13 timing attack tests added (`tests/test_timing_attacks.py`)
- 7 performance benchmark tests added (`tests/test_benchmark.py`)

### v0.2.0

OS CSPRNG + ML-KEM (FIPS 203) + Threat Model

- Lorenz anahtarı OS CSPRNG (`secrets.token_bytes(32)`) ile türetilir ve SHA-256 ile karıştırılır
- Kyber Round 3 yer tutucusu ML-KEM-768 ile değiştirildi
- STRIDE tehdit modeli eklendi

### v0.1.0

İlk sürüm (Lorenz + Kyber Round 3 + AES-GCM)

## Lisans

MIT License

## Geliştirici

Murat Uslu  
GitHub: [@uslumurat405-oss](https://github.com/uslumurat405-oss)
