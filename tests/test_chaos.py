import numpy as np

from src.crypto_engine import generate_chaos_key


def test_deterministic():
    """Manuel seed verildiğinde aynı anahtar üretilmeli."""
    seed = np.array([1.0, 2.0, 3.0], dtype=np.float64).tobytes()
    key1 = generate_chaos_key(seed)
    key2 = generate_chaos_key(seed)
    assert key1 == key2


def test_different_seeds():
    """Farklı manuel seed'ler farklı anahtar vermeli."""
    seed1 = np.array([1.0, 2.0, 3.0], dtype=np.float64).tobytes()
    seed2 = np.array([1.0, 2.0, 4.0], dtype=np.float64).tobytes()
    key1 = generate_chaos_key(seed1)
    key2 = generate_chaos_key(seed2)
    assert key1 != key2


def test_output_length():
    """Çıktı tam 32 byte olmalı."""
    seed = np.array([0.1, 0.2, 0.3], dtype=np.float64).tobytes()
    key = generate_chaos_key(seed)
    assert len(key) == 32


def test_csprng_entropy_integration():
    """OS CSPRNG ile üretilen anahtarlar rastgele ve 32 byte olmalı."""
    keys = [generate_chaos_key() for _ in range(16)]

    assert all(len(key) == 32 for key in keys)
    assert len(set(keys)) == len(keys)

    mixed = b"".join(keys)
    unique_bytes = len(set(mixed))
    assert unique_bytes > 200
