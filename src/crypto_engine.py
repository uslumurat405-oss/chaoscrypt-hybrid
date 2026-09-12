import hashlib
import os

import numpy as np
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
LORENZ_IC_BOUND = 15.0
LORENZ_STATE_BOUND = 50.0


def _seed_to_lorenz_state(seed: bytes) -> tuple[float, float, float]:
    """24 byte seed'i [-15, 15] aralığındaki Lorenz başlangıç değerlerine eşler."""
    values = np.frombuffer(seed, dtype=np.float64).astype(np.float64, copy=True)
    values = np.nan_to_num(values, nan=0.0, posinf=LORENZ_IC_BOUND, neginf=-LORENZ_IC_BOUND)

    if np.any(np.abs(values) > LORENZ_IC_BOUND):
        # Ham float64 taşmasını önlemek için her 8 byte'ı düzgün dağılımlı [-15, 15]'e çevir.
        for i in range(3):
            unit = int.from_bytes(seed[i * 8 : (i + 1) * 8], "little") / 2**64
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


def generate_chaos_key(seed: bytes, iterations: int = 10000) -> bytes:
    """
    Lorenz attractor kullanarak 256-bit şifreleme anahtarı üretir.

    Args:
        seed: 24 byte'lık başlangıç değeri (3x float64)
        iterations: Lorenz iterasyon sayısı (default: 10000)

    Returns:
        32 byte'lık SHA3-256 hash'lenmiş anahtar
    """
    if len(seed) != 24:
        raise ValueError("seed must be exactly 24 bytes")

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

    return hashlib.sha3_256(state_bytes).digest()


def generate_kyber_keys() -> tuple[bytes, bytes]:
    """
    Kyber (Lattice) anahtar çifti üretir.

    Not: Gerçek Kyber henüz entegre edilmediği için geçici olarak RSA-2048
    kullanılıyor. İleride post-kuantum Kyber implementasyonu ile değiştirilecek.
    """
    # Geçici Kyber yer tutucu: RSA-2048 anahtar çifti üret
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return public_bytes, private_bytes


def kyber_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Public key kullanarak shared secret ve ciphertext üretir (KEM encapsulation).

    32 byte rastgele shared secret oluşturulur ve RSA-OAEP ile şifrelenir.
    """
    public_key_obj = serialization.load_pem_public_key(public_key)
    shared_secret = os.urandom(32)

    ciphertext = public_key_obj.encrypt(
        shared_secret,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return shared_secret, ciphertext


def kyber_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Private key ile ciphertext'ten shared secret'i çıkarır (KEM decapsulation).
    """
    private_key_obj = serialization.load_pem_private_key(private_key, password=None)

    shared_secret = private_key_obj.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return shared_secret


def _derive_final_key(shared_secret: bytes, chaos_key: bytes) -> bytes:
    """Kyber shared secret ile chaos anahtarını birleştirerek AES anahtarı türet."""
    return hashlib.sha3_256(shared_secret + chaos_key).digest()


def hybrid_encrypt(plaintext: bytes, recipient_public_key: bytes) -> dict:
    """
    Lorenz + Kyber + AES-256-GCM hibrit şifreleme.

    Rastgele chaos seed, Kyber KEM shared secret ve AES-GCM ile plaintext şifrelenir.
    """
    chaos_seed = os.urandom(24)
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
    ardından AES-256-GCM ile plaintext elde edilir.
    """
    shared_secret = kyber_decapsulate(recipient_private_key, data["kyber_ciphertext"])
    chaos_key = generate_chaos_key(data["chaos_seed"])
    final_key = _derive_final_key(shared_secret, chaos_key)

    encrypted = data["ciphertext"]
    ciphertext = encrypted[:-GCM_TAG_SIZE]
    tag = encrypted[-GCM_TAG_SIZE:]

    cipher = AES.new(final_key, AES.MODE_GCM, nonce=data["nonce"])
    return cipher.decrypt_and_verify(ciphertext, tag)
