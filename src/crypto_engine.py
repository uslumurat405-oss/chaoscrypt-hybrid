import hashlib
import hmac
import os
import secrets

import numpy as np
from Crypto.Cipher import AES
from pqcrypto.kem.ml_kem_768 import decaps as _ml_kem_decaps
from pqcrypto.kem.ml_kem_768 import encaps as _ml_kem_encaps
from pqcrypto.kem.ml_kem_768 import keygen as _ml_kem_keygen

GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
ML_KEM_PRIVATE_KEY_SIZE = 2400
ML_KEM_CIPHERTEXT_SIZE = 1088
LORENZ_IC_BOUND = 15.0
LORENZ_STATE_BOUND = 50.0


def _bytes_to_unit_interval(chunk: bytes) -> float:
    """8 byte'ı [0, 1) aralığına çevirir."""
    return int.from_bytes(chunk, "little") / 2**64


def _seed_to_lorenz_state(seed: bytes) -> tuple[float, float, float]:
    """Seed'in ilk 24 byte'ını [-15, 15] aralığındaki Lorenz başlangıç değerlerine eşler."""
    material = seed[:24]
    if len(seed) >= 32:
        values = np.array(
            [
                _bytes_to_unit_interval(material[i * 8 : (i + 1) * 8])
                * (2.0 * LORENZ_IC_BOUND)
                - LORENZ_IC_BOUND
                for i in range(3)
            ],
            dtype=np.float64,
        )
        return tuple(values)

    values = np.frombuffer(material, dtype=np.float64).astype(np.float64, copy=True)
    values = np.nan_to_num(values, nan=0.0, posinf=LORENZ_IC_BOUND, neginf=-LORENZ_IC_BOUND)

    if np.any(np.abs(values) > LORENZ_IC_BOUND):
        # Ham float64 taşmasını önlemek için her 8 byte'ı düzgün dağılımlı [-15, 15]'e çevir.
        for i in range(3):
            unit = _bytes_to_unit_interval(material[i * 8 : (i + 1) * 8])
            values[i] = unit * (2.0 * LORENZ_IC_BOUND) - LORENZ_IC_BOUND

    return tuple(np.clip(values, -LORENZ_IC_BOUND, LORENZ_IC_BOUND))


def _stabilize_lorenz_state(x: float, y: float, z: float) -> tuple[float, float, float]:
    """Sonsuz/NaN veya aşırı büyük durumları Lorenz attractor ölçeğine geri çeker."""
    state = np.array([x, y, z], dtype=np.float64)
    if not np.all(np.isfinite(state)):
        state = np.nan_to_num(state, nan=0.0, posinf=LORENZ_STATE_BOUND, neginf=-LORENZ_STATE_BOUND)

    max_abs = np.max(np.abs(state))
    if max_abs > LORENZ_STATE_BOUND:
        state *= LORENZ_STATE_BOUND / max_abs

    return float(state[0]), float(state[1]), float(state[2])


def generate_chaos_key(seed: bytes | None = None, iterations: int = 10000) -> bytes:
    """
    Lorenz attractor kullanarak 256-bit şifreleme anahtarı üretir.

    Seed verilmezse OS CSPRNG (`secrets.token_bytes(32)`) kullanılır. Lorenz
    çıktısı bu seed ile SHA-256 üzerinden birleştirilir.

    Args:
        seed: 24 veya 32 byte'lık başlangıç değeri. None ise OS CSPRNG üretir.
        iterations: Lorenz iterasyon sayısı (default: 10000)

    Returns:
        32 byte'lık SHA-256 anahtar (kaos + CSPRNG karışımı)
    """
    if seed is None:
        seed = secrets.token_bytes(32)
    if len(seed) not in (24, 32):
        raise ValueError("seed must be 24 or 32 bytes")

    x, y, z = _seed_to_lorenz_state(seed)

    sigma = 10.0
    rho = 28.0
    beta = 8.0 / 3.0
    dt = 0.01

    with np.errstate(over="ignore", invalid="ignore", divide="ignore"):
        for _ in range(iterations):
            dx = sigma * (y - x)
            dy = x * (rho - z) - y
            dz = x * y - beta * z
            next_x = x + dt * dx
            next_y = y + dt * dy
            next_z = z + dt * dz

            if not (np.isfinite(next_x) and np.isfinite(next_y) and np.isfinite(next_z)):
                break

            x, y, z = _stabilize_lorenz_state(next_x, next_y, next_z)

    final_state = np.array([x, y, z], dtype=np.float64)
    state_bytes = final_state.tobytes()
    return hashlib.sha256(state_bytes + seed).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """
    İki bayt dizisini sabit zamanlı karşılaştırır (`hmac.compare_digest`).

    MAC tag'leri, anahtarlar ve shared secret gibi gizli bayt dizilerinde
    `==` / `!=` operatörleri ilk farklı baytta erken çıkış yapar ve zamanlama
    yan kanalı sızdırır; bu sarmalayıcı içerikten bağımsız sabit sürede çalışır.
    """
    return hmac.compare_digest(a, b)


def ml_kem_keygen() -> tuple[bytes, bytes]:
    """ML-KEM-768 (FIPS 203) public/private anahtar çifti üretir."""
    public_key, private_key = _ml_kem_keygen()
    return bytes(public_key), bytes(private_key)


def ml_kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Public key ile shared secret ve ciphertext üretir (ML-KEM encapsulation).

    Dönüş sırası mevcut API ile uyumludur: (shared_secret, ciphertext).
    """
    ciphertext, shared_secret = _ml_kem_encaps(public_key)
    return bytes(shared_secret), bytes(ciphertext)


def ml_kem_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Ciphertext'ten shared secret'i çıkarır (ML-KEM decapsulation).

    PQClean tabanlı ML-KEM-768, FO (Fujisaki-Okamoto) dönüşümünün ciphertext
    yeniden-şifreleme karşılaştırmasını sabit zamanlı yürütür ve geçersiz
    ciphertext'lerde gizli reddetme (implicit rejection) uygular; bu Python
    sarmalayıcıda secret-dependent dal yoktur. Boyut denetimi yalnızca kamu
    uzunluk bilgisi üzerinden yapılır.
    """
    if len(private_key) != ML_KEM_PRIVATE_KEY_SIZE:
        raise ValueError(f"private key must be {ML_KEM_PRIVATE_KEY_SIZE} bytes")
    if len(ciphertext) != ML_KEM_CIPHERTEXT_SIZE:
        raise ValueError(f"ciphertext must be {ML_KEM_CIPHERTEXT_SIZE} bytes")
    return bytes(_ml_kem_decaps(private_key, ciphertext))


def generate_kyber_keys() -> tuple[bytes, bytes]:
    """Kyber Round 3 yerine FIPS 203 ML-KEM-768 anahtar çifti üretir."""
    return ml_kem_keygen()


def kyber_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Mevcut Kyber API'sini ML-KEM-768 encapsulation ile karşılar."""
    return ml_kem_encapsulate(public_key)


def kyber_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """Mevcut Kyber API'sini ML-KEM-768 decapsulation ile karşılar."""
    return ml_kem_decapsulate(private_key, ciphertext)


def _derive_final_key(shared_secret: bytes, chaos_key: bytes) -> bytes:
    """Kyber shared secret ile chaos anahtarını birleştirerek AES anahtarı türet."""
    return hashlib.sha3_256(shared_secret + chaos_key).digest()


def hybrid_encrypt(plaintext: bytes, recipient_public_key: bytes) -> dict:
    """
    Lorenz + Kyber + AES-256-GCM hibrit şifreleme.

    Rastgele chaos seed, Kyber KEM shared secret ve AES-GCM ile plaintext şifrelenir.
    """
    chaos_seed = secrets.token_bytes(32)
    chaos_key = generate_chaos_key(chaos_seed)
    shared_secret, kyber_ciphertext = kyber_encapsulate(recipient_public_key)
    final_key = _derive_final_key(shared_secret, chaos_key)

    nonce = os.urandom(GCM_NONCE_SIZE)
    cipher = AES.new(final_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "ciphertext": ciphertext + tag,
        "nonce": nonce,
        "kyber_ciphertext": kyber_ciphertext,
        "chaos_seed": chaos_seed,
    }


def hybrid_decrypt(data: dict, recipient_private_key: bytes) -> bytes:
    """
    Hibrit şifreli veriyi çözer.

    Kyber decapsulation ve Lorenz anahtarı ile final AES anahtarı türetilir,
    ardından AES-256-GCM ile plaintext elde edilir. GCM tag doğrulaması
    `constant_time_equal` ile sabit zamanlı yapılır; tag eşleşmezse hata
    verilir ve plaintext hiçbir koşulda döndürülmez.
    """
    shared_secret = kyber_decapsulate(recipient_private_key, data["kyber_ciphertext"])
    chaos_key = generate_chaos_key(data["chaos_seed"])
    final_key = _derive_final_key(shared_secret, chaos_key)

    encrypted = data["ciphertext"]
    ciphertext = encrypted[:-GCM_TAG_SIZE]
    tag = encrypted[-GCM_TAG_SIZE:]

    cipher = AES.new(final_key, AES.MODE_GCM, nonce=data["nonce"])
    plaintext = cipher.decrypt(ciphertext)

    # PyCryptodome decrypt tarafında `digest()` çağrılamaz; tag'i bizim
    # tarafımızda açıkça sabit zamanlı doğrulamak için plaintext'i aynı nonce
    # ile yeniden şifreliyoruz (GCM-CTR deterministiktir, tag yeniden oluşur)
    # ve karşılaştırmayı `constant_time_equal` ile yapıyoruz. Başarılı ve
    # başarısız yollar eşit iş yapar; plaintext yalnızca eşleşmede döner.
    verifier = AES.new(final_key, AES.MODE_GCM, nonce=data["nonce"])
    verifier.encrypt(plaintext)
    computed_tag = verifier.digest()
    if not constant_time_equal(computed_tag, tag):
        raise ValueError("AES-GCM authentication failed: tag mismatch")
    return plaintext
