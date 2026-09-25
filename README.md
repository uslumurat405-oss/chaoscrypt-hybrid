
# 🔐 ChaosCrypt-Hybrid

**Post-Quantum Hibrit Şifreleme Kütüphanesi**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-96%20passed-green.svg)](tests/)
[![Coverage](https://img.shields.io/badge/coverage-95%25-brightgreen.svg)](tests/)

---

## 📖 Genel Bakış

**ChaosCrypt-Hybrid**, kuantum bilgisayar çağında bile güvenli kalacak şekilde tasarlanmış, **production-ready** bir hibrit şifreleme kütüphanesidir. 

Klasik **X25519** (Elliptic Curve) ve post-kuantum **ML-KEM-768** (NIST standardı) algoritmalarını birleştirerek, hem günümüz hem de gelecek tehditlere karşı **"belt-and-suspenders"** güvenlik yaklaşımı sunar.

### 🎯 Neden ChaosCrypt-Hybrid?

- ✅ **Kuantum Dirençli**: ML-KEM-768 ile post-kuantum saldırılara karşı koruma
- ✅ **Hibrit Güvenlik**: X25519 + ML-KEM-768 birleşimi, tek algoritma zayıflığına karşı sigorta
- ✅ **Production-Ready**: 96 test, %95+ coverage, tam tip belirtimi
- ✅ **Büyük Dosya Desteği**: 64KB chunk-based streaming ile GB'larca veriyi şifrele
- ✅ **AEAD Koruması**: Associated Data ile replay attack ve cut-and-paste saldırılarına karşı savunma

---

## 🏗️ Mimari

### 6 Kritik Güvenlik Katmanı

| Katman | Açıklama | Durum |
|--------|----------|-------|
| **1. Hibrit Anahtar Değişimi** | X25519 (klasik) + ML-KEM-768 (post-kuantum) | ✅ |
| **2. HKDF Anahtar Türetme** | SHA-256 tabanlı güvenli anahtar türetme | ✅ |
| **3. Binary Serialization** | Standart paketleme: `[version][nonce][enc_key][ciphertext][tag]` | ✅ |
| **4. AEAD Associated Data** | Meta veri bütünlüğü doğrulaması | ✅ |
| **5. Streaming Encryption** | 64KB parçalarla büyük dosya şifreleme | ✅ |
| **6. Memory Safety** | Sensitive data için güvenli hafıza temizleme | ✅ |

### Şifreleme Akışı

```text
Client → X25519 + ML-KEM-768 → HKDF → AES-256-GCM → Encrypted Output


🚀 Kurulum
Gereksinimler
Python 3.10+
cryptography kütüphanesi

Hızlı Kurulum

# Repoyu klonla
git clone https://github.com/uslumurat405-oss/chaoscrypt-hybrid.git
cd chaoscrypt-hybrid

# Virtual environment oluştur
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Bağımlılıkları yükle
pip install cryptography pytest pytest-cov

💻 Kullanım
Temel Şifreleme

from src.core import hybrid_key_exchange, derive_aes_key
from src.crypto_engine import hybrid_encrypt, hybrid_decrypt

# 1. Anahtar değişimi (alıcı ve gönderici arasında)
classic_secret, pq_secret, combined_secret = hybrid_key_exchange(
    peer_ml_kem_public_key=alici_ml_kem_pub,
    peer_x25519_public_key=alici_x25519_pub
)

# 2. AES anahtarı türet (HKDF ile)
aes_key = derive_aes_key(combined_secret)  # 32 byte AES-256 anahtarı

# 3. Şifreleme (opsiyonel associated_data ile)
plaintext = b"Gizli mesaj içeriği..."
associated_data = b"user_id:12345|timestamp:2026-09-25"

encrypted = hybrid_encrypt(
    plaintext=plaintext,
    recipient_public_key=alici_pub_key,
    associated_data=associated_data
)

# 4. Şifre çözme
decrypted = hybrid_decrypt(
    data=encrypted,
    recipient_private_key=alici_priv_key,
    associated_data=associated_data
)

assert decrypted == plaintext  # ✅ Başarılı!

Büyük Dosya Şifreleme (Streaming)


from src.crypto_engine import encrypt_stream, decrypt_stream

# 1 GB'lık dosyayı şifrele (RAM'e yüklemeden)
encrypt_stream(
    input_path="large_video.mp4",
    output_path="large_video.mp4.enc",
    key=aes_key,
    associated_data=b"file_type:video|owner:alice"
)

# Şifreyi çöz
decrypt_stream(
    input_path="large_video.mp4.enc",
    output_path="large_video_decrypted.mp4",
    key=aes_key,
    associated_data=b"file_type:video|owner:alice"
)

Binary Serialization

from src.serialization import serialize, deserialize

# Şifreli veriyi paketle
packed_data = serialize(
    nonce=nonce,              # 16 byte
    enc_key=encapsulated_key, # 1024 byte (ML-KEM)
    ciphertext=ciphertext,    # Değişken uzunluk
    tag=tag                   # 16 byte (GCM)
)

# Paket aç
nonce, enc_key, ciphertext, tag = deserialize(packed_data)


🧪 Testler
Tüm Testleri Çalıştır

pytest tests/ -v

Beklenen Çıktı:

========================= 96 passed in 54.65s =========================

Coverage Raporu

Dosya
Coverage
src/core.py
95%
src/crypto_engine.py
91%
src/hybrid_cipher.py
98%
src/serialization.py
91%
src/chaos_engine.py
100%

🔒 Güvenlik Notları
Post-Kuantum Güvenlik
ChaosCrypt-Hybrid, NIST Post-Quantum Cryptography Standardization sürecinde seçilen ML-KEM-768 (eski adıyla Kyber) algoritmasını kullanır. Bu algoritma, kuantum bilgisayarların Shor algoritması ile klasik elliptic curve kriptografisini kırmasına karşı dirençlidir.
Hibrit Yaklaşım
NIST'in önerdiği "belt-and-suspenders" (kemer ve askı) yaklaşımını benimser:
X25519: Kanıtlanmış, geniş çapta kullanılan klasik algoritma
ML-KEM-768: Post-kuantum dirençli yeni nesil algoritma
Her iki algoritmanın aynı anda kırılması gerektiğinden, güvenlik marjı katlanarak artar.
AEAD Koruması
Associated Data özelliği, şifrelenmeyen meta verilerin (kullanıcı ID, timestamp, dosya başlığı) bütünlüğünü korur. Bu, şu saldırıları önler:
Replay Attack: Eski şifreli mesajların tekrar gönderilmesi
Cut-and-Paste Attack: Farklı mesajların parçalarının birleştirilmesi
Memory Safety
Python'da garbage collector nedeniyle %100 secure wiping garanti edilemez. Ancak bytearray ve ctypes.memset ile mitigation sağlanır. Tam güvenlik için Rust/C implementasyonu önerilir.


chaoscrypt-hybrid/
├── src/
│   ├── core.py              # Hibrit anahtar değişimi + HKDF
│   ├── crypto_engine.py     # AES-GCM şifreleme + streaming
│   ├── hybrid_cipher.py     # Yüksek seviye şifreleme API
│   ├── serialization.py     # Binary paketleme
│   ├── chaos_engine.py      # Kaotik CSPRNG
│   └── chaotic_csprng.py    # Lorenz tabanlı rastgele sayı üreteci
├── tests/
│   ├── test_core.py         # 27 test
│   ├── test_crypto_engine.py # 7 test
│   ├── test_hybrid_cipher.py # 12 test
│   ├── test_serialization.py # 13 test
│   └── ...
├── README.md
├── SECURITY.md
├── THREAT_MODEL.md
└── requirements.txt


🤝 Katkıda Bulunma
Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:
Fork yapın
Feature branch oluşturun (git checkout -b feature/amazing-feature)
Commit yapın (git commit -m 'Add amazing feature')
Push yapın (git push origin feature/amazing-feature)
Pull Request açın

Test Yazma

Yeni özellik eklerseniz, lütfen karşılık gelen testleri de ekleyin:

pytest tests/ -v --cov=src

Coverage %90'ın altına düşmemelidir.


📄 Lisans

Bu proje MIT License altında lisanslanmıştır. Detaylar için LICENSE dosyasına bakın.

🙏 Teşekkürler

NIST: Post-kuantum kriptografi standartları için
Python cryptography kütüphanesi: Güvenli kriptografik primitifler için
Açık kaynak topluluğu: İlham ve destek için


📬 İletişim
GitHub Issues: Bug report veya feature request
GitHub: uslumurat405-oss



<div align="center">

Made with 🔒 by Murat Uslu
⭐ Star this repo if you find it useful!
</div>





