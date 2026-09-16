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

## Test

```bash
python -m pytest tests/ -v
```

## Mimari

```
Plaintext → [Lorenz Key + OS CSPRNG] + [ML-KEM-768 Shared Secret] → AES-256-GCM → Ciphertext
```

## Güvenlik Durumu

- ✅ OS CSPRNG entegrasyonu (FIPS 203 uyumlu)
- ✅ ML-KEM-768 (NIST FIPS 203 standardı)
- ✅ AES-256-GCM authenticated encryption
- ✅ 23/23 test geçti
- ✅ STRIDE threat model dokümante edildi (`THREAT_MODEL.md`)
- ⚠️ Side-channel koruması planlanıyor
- ⚠️ Formal security proof araştırma aşamasında

## Güvenlik Notu

Bu proje araştırma amaçlıdır. Production kullanımı için profesyonel security audit gereklidir.

## Changelog

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
