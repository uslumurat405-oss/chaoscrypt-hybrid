import os

import pytest

from src.crypto_engine import (
    CHUNK_SIZE,
    decrypt_stream,
    encrypt_stream,
)


@pytest.fixture
def aes_key() -> bytes:
    """Şifreleme testleri için 32 byte'lık rastgele AES-256 anahtarı üretir."""
    return os.urandom(32)


def _write_file(path: str, data: bytes) -> None:
    """Verilen yola bayt verisini yazar."""
    with open(path, "wb") as f:
        f.write(data)


def _read_file(path: str) -> bytes:
    """Verilen yoldan bayt verisini okur."""
    with open(path, "rb") as f:
        return f.read()


def test_stream_roundtrip_small_file(tmp_path, aes_key):
    """1KB'lık küçük dosya şifrelenip çözüldüğünde orijinal içeriğe dönmeli."""
    plaintext = os.urandom(1024)
    input_path = str(tmp_path / "small.bin")
    encrypted_path = str(tmp_path / "small.bin.enc")
    decrypted_path = str(tmp_path / "small.bin.dec")

    _write_file(input_path, plaintext)

    encrypt_stream(input_path, encrypted_path, aes_key)
    decrypt_stream(encrypted_path, decrypted_path, aes_key)

    assert _read_file(decrypted_path) == plaintext


def test_stream_roundtrip_medium_file(tmp_path, aes_key):
    """1MB'lık orta boy dosya (16 chunk) turlanmalı; chunk sınırları aşılır."""
    plaintext = os.urandom(1024 * 1024)
    input_path = str(tmp_path / "medium.bin")
    encrypted_path = str(tmp_path / "medium.bin.enc")
    decrypted_path = str(tmp_path / "medium.bin.dec")

    _write_file(input_path, plaintext)

    encrypt_stream(input_path, encrypted_path, aes_key)
    decrypt_stream(encrypted_path, decrypted_path, aes_key)

    assert _read_file(decrypted_path) == plaintext


def test_stream_roundtrip_large_file(tmp_path, aes_key):
    """10MB'lık büyük dosya (160 chunk) belleğe tam yüklenmeden turlanmalı."""
    plaintext = os.urandom(10 * 1024 * 1024)
    input_path = str(tmp_path / "large.bin")
    encrypted_path = str(tmp_path / "large.bin.enc")
    decrypted_path = str(tmp_path / "large.bin.dec")

    _write_file(input_path, plaintext)

    encrypt_stream(input_path, encrypted_path, aes_key)
    decrypt_stream(encrypted_path, decrypted_path, aes_key)

    assert _read_file(decrypted_path) == plaintext


def test_stream_missing_input_path_raises_filenotfounderror(tmp_path, aes_key):
    """Var olmayan girdi dosyası hem şifrelemede hem çözmede FileNotFoundError üretmeli."""
    missing_path = str(tmp_path / "does_not_exist.bin")
    output_path = str(tmp_path / "out.bin")

    with pytest.raises(FileNotFoundError):
        encrypt_stream(missing_path, output_path, aes_key)

    with pytest.raises(FileNotFoundError):
        decrypt_stream(missing_path, output_path, aes_key)


def test_stream_invalid_key_length_raises_valueerror(tmp_path, aes_key):
    """Geçersiz uzunlukta anahtar hem şifrelemede hem çözmede ValueError üretmeli."""
    input_path = str(tmp_path / "input.bin")
    output_path = str(tmp_path / "output.bin")
    _write_file(input_path, b"stream key validation data")

    for bad_key in (b"short", os.urandom(16), os.urandom(24), os.urandom(64)):
        with pytest.raises(ValueError):
            encrypt_stream(input_path, output_path, bad_key)

        with pytest.raises(ValueError):
            decrypt_stream(input_path, output_path, bad_key)


def test_stream_roundtrip_with_associated_data(tmp_path, aes_key):
    """associated_data ile tur orijinali vermeli; farklı AAD tag hatasına düşmeli."""
    plaintext = os.urandom(3 * CHUNK_SIZE + 500)
    associated_data = b"user_id:123|timestamp:2026"
    input_path = str(tmp_path / "aad.bin")
    encrypted_path = str(tmp_path / "aad.bin.enc")
    decrypted_path = str(tmp_path / "aad.bin.dec")

    _write_file(input_path, plaintext)

    encrypt_stream(input_path, encrypted_path, aes_key, associated_data)
    decrypt_stream(encrypted_path, decrypted_path, aes_key, associated_data)

    assert _read_file(decrypted_path) == plaintext

    with pytest.raises(ValueError):
        decrypt_stream(encrypted_path, decrypted_path, aes_key, b"tampered_aad")


def test_stream_tampered_encrypted_file_raises_valueerror(tmp_path, aes_key):
    """Şifreli dosyanın bir chunk'ı değiştirilirse çözme ValueError üretmeli."""
    plaintext = os.urandom(3 * CHUNK_SIZE + 500)
    input_path = str(tmp_path / "tamper.bin")
    encrypted_path = str(tmp_path / "tamper.bin.enc")
    decrypted_path = str(tmp_path / "tamper.bin.dec")

    _write_file(input_path, plaintext)
    encrypt_stream(input_path, encrypted_path, aes_key)

    encrypted = bytearray(_read_file(encrypted_path))
    encrypted[len(encrypted) // 2] ^= 0xFF
    _write_file(encrypted_path, bytes(encrypted))

    with pytest.raises(ValueError):
        decrypt_stream(encrypted_path, decrypted_path, aes_key)
