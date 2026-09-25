"""
Binary serialization for ChaosCrypt-Hybrid encrypted payloads.

Wire format (little-endian):

    [1 byte version][16 byte nonce][1024 byte encapsulated key]
    [ciphertext (variable)][16 byte tag]
"""

import struct

VERSION = 0x01
NONCE_SIZE = 16
ENCAPSULATED_KEY_SIZE = 1024
TAG_SIZE = 16

HEADER_FORMAT = "<B16s1024s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MIN_DATA_SIZE = HEADER_SIZE + TAG_SIZE


def _validate_fixed_field(name: str, value: bytes, expected_size: int) -> None:
    """Raise ValueError unless value is bytes with the expected length."""
    if not isinstance(value, bytes):
        raise ValueError(f"{name} must be bytes")
    if len(value) != expected_size:
        raise ValueError(f"{name} must be {expected_size} bytes")


def serialize(nonce: bytes, enc_key: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Serialize an encrypted payload into the binary wire format.

    Layout: version (1 byte) || nonce (16 bytes) || encapsulated key
    (1024 bytes) || ciphertext (variable) || tag (16 bytes), packed
    little-endian.

    Args:
        nonce: 16-byte nonce.
        enc_key: 1024-byte encapsulated key.
        ciphertext: Variable-length ciphertext (may be empty).
        tag: 16-byte authentication tag.

    Returns:
        The serialized payload as bytes.

    Raises:
        ValueError: If nonce, enc_key, or tag is not bytes or has an invalid
            length, or if ciphertext is not bytes.
    """
    # "Ns" struct fields silently pad/truncate, so lengths are validated
    # before packing.
    _validate_fixed_field("nonce", nonce, NONCE_SIZE)
    _validate_fixed_field("enc_key", enc_key, ENCAPSULATED_KEY_SIZE)
    if not isinstance(ciphertext, bytes):
        raise ValueError("ciphertext must be bytes")
    _validate_fixed_field("tag", tag, TAG_SIZE)

    header = struct.pack(HEADER_FORMAT, VERSION, nonce, enc_key)
    return header + ciphertext + tag


def deserialize(data: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Deserialize a payload produced by serialize() into its components.

    Args:
        data: Serialized payload bytes.

    Returns:
        Tuple (nonce, enc_key, ciphertext, tag).

    Raises:
        ValueError: If data is not bytes, is shorter than the minimum valid
            payload size, or carries an unsupported version byte.
    """
    if not isinstance(data, bytes):
        raise ValueError("data must be bytes")
    if len(data) < MIN_DATA_SIZE:
        raise ValueError(
            f"data must be at least {MIN_DATA_SIZE} bytes, got {len(data)}"
        )

    version, nonce, enc_key = struct.unpack_from(HEADER_FORMAT, data, 0)
    if version != VERSION:
        raise ValueError(
            f"unsupported version byte: 0x{version:02x} (expected 0x{VERSION:02x})"
        )

    ciphertext = data[HEADER_SIZE : len(data) - TAG_SIZE]
    tag = data[len(data) - TAG_SIZE :]
    return nonce, enc_key, ciphertext, tag
