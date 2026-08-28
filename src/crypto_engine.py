import hashlib
import os

import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


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

    x, y, z = np.frombuffer(seed, dtype=np.float64)

    sigma = 10.0
    rho = 28.0
    beta = 8.0 / 3.0
    dt = 0.01

    for _ in range(iterations):
        dx = sigma * (y - x)
        dy = x * (rho - z) - y
        dz = x * y - beta * z
        x = x + dt * dx
        y = y + dt * dy
        z = z + dt * dz

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
