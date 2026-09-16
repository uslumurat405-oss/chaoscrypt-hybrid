import pytest
import os
import tempfile
from src.hybrid_cipher import HybridCipher

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
