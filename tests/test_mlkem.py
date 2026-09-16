from src.crypto_engine import (
    generate_kyber_keys,
    kyber_decapsulate,
    kyber_encapsulate,
    ml_kem_decapsulate,
    ml_kem_encapsulate,
    ml_kem_keygen,
)


def test_mlkem_key_generation():
    """ML-KEM-768 public ve private key çifti üretilmeli."""
    public_key, private_key = ml_kem_keygen()

    assert isinstance(public_key, bytes)
    assert isinstance(private_key, bytes)
    assert len(public_key) == 1184
    assert len(private_key) == 2400
    assert public_key != private_key


def test_mlkem_encapsulate_decapsulate():
    """Encapsulate edilen shared secret, decapsulate ile aynı olmalı."""
    public_key, private_key = ml_kem_keygen()
    shared_secret, ciphertext = ml_kem_encapsulate(public_key)
    recovered_secret = ml_kem_decapsulate(private_key, ciphertext)

    assert recovered_secret == shared_secret
    assert len(ciphertext) == 1088


def test_shared_secret_is_32_bytes():
    """Shared secret tam 32 byte olmalı."""
    public_key, _ = ml_kem_keygen()
    shared_secret, _ = ml_kem_encapsulate(public_key)

    assert len(shared_secret) == 32


def test_kyber_api_aliases_ml_kem():
    """Eski Kyber API'si ML-KEM-768 ile aynı davranmalı."""
    public_key, private_key = generate_kyber_keys()
    shared_secret, ciphertext = kyber_encapsulate(public_key)
    recovered_secret = kyber_decapsulate(private_key, ciphertext)

    assert recovered_secret == shared_secret
    assert len(public_key) == 1184
    assert len(shared_secret) == 32
