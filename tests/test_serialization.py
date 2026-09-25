"""
Tests for the binary serialization of encrypted payloads in src/serialization.py.

Covers the serialize/deserialize round-trip across ciphertext lengths, the
wire-format layout and version byte, and the ValueError paths for invalid
field sizes and corrupted or truncated data.
"""

import pytest

from src.serialization import deserialize, serialize

VERSION = 0x01
NONCE_SIZE = 16
ENCAPSULATED_KEY_SIZE = 1024
TAG_SIZE = 16
HEADER_SIZE = 1 + NONCE_SIZE + ENCAPSULATED_KEY_SIZE

SAMPLE_NONCE = bytes(range(NONCE_SIZE))
SAMPLE_ENC_KEY = bytes(range(256)) * 4
SAMPLE_TAG = b"\xa5" * TAG_SIZE


def test_roundtrip_returns_original_data():
    """Serialize then deserialize must return the original components."""
    ciphertext = b"roundtrip payload"

    data = serialize(SAMPLE_NONCE, SAMPLE_ENC_KEY, ciphertext, SAMPLE_TAG)

    assert deserialize(data) == (SAMPLE_NONCE, SAMPLE_ENC_KEY, ciphertext, SAMPLE_TAG)


@pytest.mark.parametrize(
    "ciphertext_length",
    [16, 256, 1024],
    ids=["16B", "256B", "1024B"],
)
def test_roundtrip_various_ciphertext_lengths(ciphertext_length):
    """Round-trip must preserve ciphertexts of 16, 256, and 1024 bytes."""
    ciphertext = b"\x5c" * ciphertext_length

    data = serialize(SAMPLE_NONCE, SAMPLE_ENC_KEY, ciphertext, SAMPLE_TAG)
    nonce, enc_key, restored_ciphertext, tag = deserialize(data)

    assert nonce == SAMPLE_NONCE
    assert enc_key == SAMPLE_ENC_KEY
    assert restored_ciphertext == ciphertext
    assert tag == SAMPLE_TAG


def test_empty_ciphertext_roundtrip():
    """A payload with an empty ciphertext must round-trip at minimum size."""
    data = serialize(SAMPLE_NONCE, SAMPLE_ENC_KEY, b"", SAMPLE_TAG)

    assert len(data) == HEADER_SIZE + TAG_SIZE
    assert deserialize(data) == (SAMPLE_NONCE, SAMPLE_ENC_KEY, b"", SAMPLE_TAG)


def test_version_byte_is_0x01():
    """The serialized payload must start with version byte 0x01."""
    data = serialize(SAMPLE_NONCE, SAMPLE_ENC_KEY, b"payload", SAMPLE_TAG)

    assert data[0] == VERSION


def test_wire_layout_matches_specification():
    """Fixed fields must sit at their specified offsets in the wire format."""
    ciphertext = b"\x77" * 32

    data = serialize(SAMPLE_NONCE, SAMPLE_ENC_KEY, ciphertext, SAMPLE_TAG)

    assert len(data) == HEADER_SIZE + len(ciphertext) + TAG_SIZE
    assert data[1 : 1 + NONCE_SIZE] == SAMPLE_NONCE
    assert data[1 + NONCE_SIZE : HEADER_SIZE] == SAMPLE_ENC_KEY
    assert data[HEADER_SIZE : HEADER_SIZE + len(ciphertext)] == ciphertext
    assert data[-TAG_SIZE:] == SAMPLE_TAG


def test_nonce_with_15_bytes_raises_value_error():
    """A 15-byte nonce must raise ValueError."""
    with pytest.raises(ValueError, match="nonce"):
        serialize(b"\x00" * 15, SAMPLE_ENC_KEY, b"payload", SAMPLE_TAG)


def test_enc_key_with_1023_bytes_raises_value_error():
    """A 1023-byte enc_key must raise ValueError."""
    with pytest.raises(ValueError, match="enc_key"):
        serialize(SAMPLE_NONCE, b"\x00" * 1023, b"payload", SAMPLE_TAG)


def test_tag_with_15_bytes_raises_value_error():
    """A 15-byte tag must raise ValueError."""
    with pytest.raises(ValueError, match="tag"):
        serialize(SAMPLE_NONCE, SAMPLE_ENC_KEY, b"payload", b"\x00" * 15)


def test_empty_data_raises_value_error():
    """Deserializing empty data must raise ValueError."""
    with pytest.raises(ValueError):
        deserialize(b"")


def test_truncated_data_raises_value_error():
    """Data shorter than the minimum valid payload must raise ValueError."""
    data = serialize(SAMPLE_NONCE, SAMPLE_ENC_KEY, b"payload", SAMPLE_TAG)

    with pytest.raises(ValueError, match="at least"):
        deserialize(data[: HEADER_SIZE + TAG_SIZE - 1])


def test_unsupported_version_raises_value_error():
    """An unsupported version byte must raise ValueError."""
    data = serialize(SAMPLE_NONCE, SAMPLE_ENC_KEY, b"payload", SAMPLE_TAG)

    with pytest.raises(ValueError, match="version"):
        deserialize(b"\x02" + data[1:])
