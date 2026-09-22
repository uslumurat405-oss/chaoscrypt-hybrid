# ChaosCrypt-Hybrid Threat Model

**Kapsam:** Lorenz + ML-KEM-768 (FIPS 203) + AES-256-GCM hibrit şifreleme motoru (`src/crypto_engine.py`)  
**Yöntem:** STRIDE  
**Durum:** Akademik / araştırma prototipi — birim testlerinin geçmesi güvenlik kanıtı değildir.

## Sistem özeti

| Bileşen | Rol |
|---|---|
| OS CSPRNG (`secrets.token_bytes`) | 256-bit Lorenz seed |
| Lorenz attractor + SHA-256 | Kaotik anahtar türetimi |
| ML-KEM-768 | Post-kuantum anahtar kapsülleme |
| AES-256-GCM | Gizlilik + bütünlük |

Şifreli paket: `ciphertext` (GCM ciphertext + tag), `nonce` (12 byte), `kyber_ciphertext`, `chaos_seed`.  
`chaos_seed` paket içinde açık taşınır; gizlilik ML-KEM shared secret ile birleştirmeye bağlıdır.

**Korunan varlıklar:** plaintext, alıcı private key, türetilmiş AES anahtarı, ML-KEM shared secret.  
**Güven sınırları:** uygulama süreci, OS CSPRNG, `pqcrypto` ML-KEM implementasyonu.

---

## 1. Spoofing (Kimlik sahteciliği)

**Saldırı senaryosu.** Saldırgan, gönderenin kullandığı alıcı public key’ini kendi ML-KEM-768 anahtarıyla değiştirir (anahtar değiştirme / machine-in-the-middle). Mesaj saldırganın private key’i ile açılır.

**Mevcut savunma.** Kapsülleme ML-KEM-768 (FIPS 203) ile yapılır; yalnızca eşleşen private key shared secret’i üretir. Yanlış anahtarla `hybrid_decrypt` başarısız olur. Public key’in kendisi henüz imza veya sertifika ile doğrulanmaz.

**Risk:** Orta

**Gelecek iyileştirmeler**
- Alıcı public key’ini ML-DSA (FIPS 204) ile imzala / sabitle
- Anahtar parmak izi (TOFU) veya PKI
- Authenticated KEM veya hybrid AKE

---

## 2. Tampering (Veri değiştirme)

**Saldırı senaryosu.** Saldırgan şifreli paketteki ciphertext, nonce, `kyber_ciphertext` veya `chaos_seed` alanlarını değiştirir. Amaç plaintext’i bozmak veya sahte içerik üretmek.

**Mevcut savunma.** AES-256-GCM authentication tag (16 byte) ciphertext'e bağlıdır. Tag doğrulanmazsa çözme, `constant_time_equal` (`hmac.compare_digest`) ile yapılan sabit zamanlı doğrulama tarafından reddedilir. Anahtar `SHA3-256(ML-KEM shared secret ‖ chaos_key)` ile türetilir; paketin herhangi bir parçasının değiştirilmesi büyük olasılıkla GCM doğrulamasını düşürür.

**Risk:** Düşük

**Gelecek iyileştirmeler**
- Tüm paket alanlarını (nonce, KEM ciphertext, chaos seed) AAD olarak GCM’e bağla
- Canonical serialization ve sürüm alanı
- Replay’e karşı monoton sayaç / timestamp (AAD içinde)

---

## 3. Repudiation (İnkar)

**Saldırı senaryosu.** Gönderen, belirli bir ciphertext’i kendisinin üretmediğini iddia eder. Protokolde gönderen kimliği bağlayan bir kanıt yoktur.

**Mevcut savunma.** Yok. ML-KEM encapsulation göndereni doğrulamaz; AES-GCM alıcıya bütünlük sağlar, üçüncü tarafa inkâr edilemezlik sağlamaz.

**Risk:** Düşük (mevcut hedef: gizlilik + bütünlük, inkâr edilemezlik değil)

**Gelecek iyileştirmeler**
- Post-kuantum dijital imza (ML-DSA / FIPS 204)
- İmzanın plaintext veya GCM AAD üzerine alınması
- Anahtar kullanım kayıtları (audit log)

---

## 4. Information Disclosure (Bilgi sızması)

**Saldırı senaryosu.** Saldırgan timing, önbellek veya güç analizi ile Lorenz iterasyonlarından, Python/float yolundan veya ML-KEM decapsulation’dan anahtar materyali sızdırır. `chaos_seed` zaten paketle birlikte açıktır; asıl sır ML-KEM shared secret ve türetilmiş AES anahtarıdır.

**Mevcut savunma.** AES-256-GCM gizliliği; OS CSPRNG seed; SHA-256 ile kaos çıktısının CSPRNG seed ile karıştırılması. GCM tag doğrulaması ve gizli bayt karşılaştırmaları `hmac.compare_digest` üzerinden sabit zamanlı yapılır (`constant_time_equal`); ML-KEM decapsulation girdi boyutları yalnızca kamu uzunluk bilgisiyle doğrulanır ve implicit rejection sabit zamanlı PQClean yolunu kullanır. `tests/test_timing_attacks.py`, karşılaştırma ve decapsulation zamanlamasını istatistiksel olarak ölçer. Lorenz Euler adımları ve NumPy `float64` işlemleri constant-time değildir.

**Risk:** Yüksek

**Gelecek iyileştirmeler**
- Secret-dependent branch temizliği (kalan kısım; sabit zamanlı karşılaştırma tamamlandı)
- Lorenz’i kriptografik primitive olarak değil, yalnızca ek entropy karıştırıcı olarak tutmak
- Side-channel değerlendirmesi (Dudect / TVLA) ve sızdırmaz ML-KEM yolu
- Secret’lerin `bytes` üzerinde mümkün olduğunca kısa ömürlü tutulması ve sıfırlanması

---

## 5. Denial of Service (Hizmet reddi)

**Saldırı senaryosu.** Saldırgan çok sayıda `hybrid_encrypt` / `hybrid_decrypt` veya 10.000 Lorenz iterasyonu tetikleyerek CPU ve bellek tüketir. Bozuk paketler tekrarlayan başarısız decapsulate/decrypt döngülerine zorlanabilir.

**Mevcut savunma.** Yok (rate limiting, istek kotası veya maliyet sınırı uygulanmıyor). GCM tag hatası erken reddeder; bu DoS’u sınırlamaz.

**Risk:** Orta

**Gelecek iyileştirmeler**
- Rate limiting ve maksimum mesaj boyutu
- Lorenz iterasyon tavanı ve CPU bütçesi
- Hatalı paketlerde sabit maliyetli fail (timing sızıntısını da azaltır)

---

## 6. Elevation of Privilege (Yetki yükseltme)

**Saldırı senaryosu.** Saldırgan malformed ciphertext veya anahtar baytlarıyla bellek bozulması, interpreter kaçışı veya process yetkisi yükseltmeyi hedefler (klasik buffer overflow).

**Mevcut savunma.** Python bellek güvenliği (sınır denetimli nesneler). KEM `pqcrypto` native uzantısındadır; bu sınır C/Rust FFI riskini taşır. Uygulama sandbox veya privilege dropping uygulamaz.

**Risk:** Düşük

**Gelecek iyileştirmeler**
- `pqcrypto` ve PyCryptodome sürümlerini pin’lemek, SBOM / bağımlılık taraması
- Fuzzing (`hybrid_decrypt` ve ML-KEM decapsulate)
- En düşük yetki ile çalıştırma (container / seccomp)

---

## Risk özeti

| STRIDE | Tehdit | Risk | Mevcut kontrol |
|---|---|---|---|
| S | Anahtar değiştirme | Orta | ML-KEM-768; public key kimliği yok |
| T | Şifreli paket değiştirme | Düşük | AES-256-GCM tag |
| R | Gönderenin inkarı | Düşük | İmza yok (kabul edilen boşluk) |
| I | Side-channel | Yüksek | CSPRNG + GCM; sabit zamanlı karşılaştırma (Lorenz yolu hariç) |
| D | Kaynak tüketme | Orta | Rate limit yok |
| E | Bellek bozulması | Düşük | Python memory safety |

## Bilinçli sınırlar

1. Unit test ve round-trip başarıları kriptografik kanıt değildir.
2. Lorenz attractor tek başına CSPRNG yerine geçmez; OS CSPRNG ve ML-KEM asıl güvenlik varsayımlarıdır.
3. Public key dağıtımı, imza ve side-channel direnci henüz tehdit modelindeki açık maddelerdir.
4. Bu belge bir güvence raporu değil, mühendislik tehdit envanteridir.
