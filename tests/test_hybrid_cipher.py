import pytest
import os
import tempfile
from src.hybrid_cipher import HybridCipher
from src.crypto_engine import (
    generate_kyber_keys,
    hybrid_decrypt,
    hybrid_encrypt,
)

@pytest.fixture
def cipher():
    return HybridCipher()

def test_encrypt_decrypt_roundtrip(cipher):
    plaintext = b"Hello ChaosCrypt! This is a test."
    encrypted = cipher.encrypt(plaintext, "password123")
    decrypted = cipher.decrypt(encrypted, "password123")
    assert plaintext == decrypted

def test_wrong_password(cipher):
    plaintext = b"Secret data"
    encrypted = cipher.encrypt(plaintext, "correct_password")
    with pytest.raises(ValueError):
        cipher.decrypt(encrypted, "wrong_password")

def test_tampered_data(cipher):
    plaintext = b"Important data"
    encrypted = bytearray(cipher.encrypt(plaintext, "password"))
    encrypted[-1] ^= 0xFF
    with pytest.raises(ValueError):
        cipher.decrypt(bytes(encrypted), "password")

def test_different_nonce_each_time(cipher):
    plaintext = b"Same message"
    enc1 = cipher.encrypt(plaintext, "password")
    enc2 = cipher.encrypt(plaintext, "password")
    assert enc1 != enc2

def test_large_data(cipher):
    plaintext = os.urandom(10 * 1024 * 1024)
    encrypted = cipher.encrypt(plaintext, "password")
    decrypted = cipher.decrypt(encrypted, "password")
    assert plaintext == decrypted

def test_file_encrypt_decrypt(cipher):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
        f.write(b"File content test")
        input_path = f.name
    
    enc_path = input_path + '.enc'
    dec_path = input_path + '.dec'
    
    try:
        cipher.encrypt_file(input_path, "password", enc_path)
        cipher.decrypt_file(enc_path, "password", dec_path)
        
        with open(input_path, 'rb') as f1, open(dec_path, 'rb') as f2:
            assert f1.read() == f2.read()
    finally:
        for p in [input_path, enc_path, dec_path]:
            if os.path.exists(p):
                os.unlink(p)


def test_hybrid_encrypt_decrypt_with_associated_data():
    """Geçerli associated_data ile şifrele/çöz turu orijinal metni döndürmeli."""
    public_key, private_key = generate_kyber_keys()
    plaintext = b"Secret AEAD message"
    associated_data = b"user_id:123|timestamp:2026"

    encrypted = hybrid_encrypt(plaintext, public_key, associated_data)
    decrypted = hybrid_decrypt(encrypted, private_key, associated_data)

    assert decrypted == plaintext


def test_hybrid_decrypt_fails_with_tampered_associated_data():
    """associated_data değiştirilir veya ihmal edilirse tag doğrulaması başarısız olmalı."""
    public_key, private_key = generate_kyber_keys()
    plaintext = b"Secret AEAD message"
    associated_data = b"user_id:123|timestamp:2026"

    encrypted = hybrid_encrypt(plaintext, public_key, associated_data)

    with pytest.raises(ValueError):
        hybrid_decrypt(encrypted, private_key, b"user_id:123|timestamp:9999")

    with pytest.raises(ValueError):
        hybrid_decrypt(encrypted, private_key)


def test_hybrid_backward_compatibility_without_associated_data():
    """associated_data verilmediğinde eski iki parametreli davranış korunmalı."""
    public_key, private_key = generate_kyber_keys()
    plaintext = b"Legacy message"

    encrypted = hybrid_encrypt(plaintext, public_key)
    decrypted = hybrid_decrypt(encrypted, private_key)

    assert decrypted == plaintext


def test_hybrid_with_empty_associated_data():
    """Boş associated_data (b"") ile şifrele/çöz turu çalışmalı."""
    public_key, private_key = generate_kyber_keys()
    plaintext = b"Empty AAD message"

    encrypted = hybrid_encrypt(plaintext, public_key, b"")
    decrypted = hybrid_decrypt(encrypted, private_key, b"")

    assert decrypted == plaintext


def test_hybrid_with_large_associated_data():
    """1KB'lık büyük associated_data ile şifrele/çöz turu çalışmalı."""
    public_key, private_key = generate_kyber_keys()
    plaintext = b"Large AAD message"
    associated_data = os.urandom(1024)

    encrypted = hybrid_encrypt(plaintext, public_key, associated_data)
    decrypted = hybrid_decrypt(encrypted, private_key, associated_data)

    assert decrypted == plaintext


def test_hybrid_associated_data_wrong_type_raises_valueerror():
    """bytes olmayan associated_data hem şifrelemede hem çözmede ValueError üretmeli."""
    public_key, private_key = generate_kyber_keys()
    plaintext = b"Type check message"
    associated_data = "user_id:123|timestamp:2026"

    with pytest.raises(ValueError):
        hybrid_encrypt(plaintext, public_key, associated_data)

    encrypted = hybrid_encrypt(plaintext, public_key)
    with pytest.raises(ValueError):
        hybrid_decrypt(encrypted, private_key, associated_data)
