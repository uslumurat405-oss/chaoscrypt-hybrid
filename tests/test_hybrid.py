import pytest

from src.crypto_engine import (
    generate_kyber_keys,
    hybrid_decrypt,
    hybrid_encrypt,
)


def test_hybrid_roundtrip():
    """Encrypt → decrypt orijinal metni geri vermeli."""
    public_key, private_key = generate_kyber_keys()
    plaintext = b"ChaosCrypt-Hybrid mesaji"

    encrypted = hybrid_encrypt(plaintext, public_key)
    decrypted = hybrid_decrypt(encrypted, private_key)

    assert decrypted == plaintext
    assert len(encrypted["chaos_seed"]) == 32
    assert hybrid_decrypt(encrypted, private_key) == plaintext


def test_different_plaintexts():
    """Farklı metinler farklı ciphertext üretmeli."""
    public_key, _ = generate_kyber_keys()
    plaintext1 = b"mesaj bir"
    plaintext2 = b"mesaj iki"

    encrypted1 = hybrid_encrypt(plaintext1, public_key)
    encrypted2 = hybrid_encrypt(plaintext2, public_key)

    assert encrypted1["ciphertext"] != encrypted2["ciphertext"]


def test_wrong_key_fails():
    """Yanlış private key ile decrypt hata vermeli."""
    public_key, _ = generate_kyber_keys()
    _, wrong_private_key = generate_kyber_keys()
    plaintext = b"gizli veri"

    encrypted = hybrid_encrypt(plaintext, public_key)

    with pytest.raises(Exception):
        hybrid_decrypt(encrypted, wrong_private_key)
