from src.crypto_engine import (
    generate_kyber_keys,
    kyber_decapsulate,
    kyber_encapsulate,
)


def test_kyber_key_generation():
    """Public ve private key çifti üretilmeli."""
    public_key, private_key = generate_kyber_keys()

    assert isinstance(public_key, bytes)
    assert isinstance(private_key, bytes)
    assert len(public_key) > 0
    assert len(private_key) > 0
    assert public_key != private_key


def test_kyber_encapsulate_decapsulate():
    """Encapsulate edilen shared secret, decapsulate ile aynı olmalı."""
    public_key, private_key = generate_kyber_keys()
    shared_secret, ciphertext = kyber_encapsulate(public_key)
    recovered_secret = kyber_decapsulate(private_key, ciphertext)

    assert recovered_secret == shared_secret


def test_shared_secret_is_32_bytes():
    """Shared secret tam 32 byte olmalı."""
    public_key, _ = generate_kyber_keys()
    shared_secret, _ = kyber_encapsulate(public_key)

    assert len(shared_secret) == 32
