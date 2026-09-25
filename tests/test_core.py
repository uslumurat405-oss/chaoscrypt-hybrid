"""
Tests for the hybrid X25519 + ML-KEM-768 key exchange and the HKDF-SHA256
AES key derivation in src/core.py.

Covers the success path (return shape and secret lengths), the classic || pq
concatenation contract, freshness of ephemeral keys, mocked ML-KEM call
contracts, the ValueError paths for invalid peer public keys, and the
derive_aes_key contract (output size, determinism, and input validation).
"""

from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from src.core import derive_aes_key, hybrid_key_exchange
from src.crypto_engine import ml_kem_keygen

CLASSIC_SECRET_SIZE = 32
PQ_SECRET_SIZE = 32
COMBINED_SECRET_SIZE = 64
AES_KEY_SIZE = 32

SAMPLE_SHARED_SECRET = bytes(range(64))
ALTERNATE_SHARED_SECRET = b"\xff" * 64


@pytest.fixture(scope="module")
def peer_keys() -> tuple[bytes, bytes]:
    """Return a valid peer key pair: (ML-KEM-768 public key, X25519 public key)."""
    ml_kem_public_key, _ = ml_kem_keygen()
    x25519_public_key = (
        X25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return ml_kem_public_key, x25519_public_key


def test_returns_tuple_of_three_bytes(peer_keys):
    """A successful exchange returns a tuple of exactly three bytes values."""
    result = hybrid_key_exchange(*peer_keys)

    assert isinstance(result, tuple)
    assert len(result) == 3
    assert all(isinstance(value, bytes) for value in result)


def test_classic_shared_secret_is_32_bytes(peer_keys):
    """The X25519 classic shared secret must be exactly 32 bytes."""
    classic_shared_secret, _, _ = hybrid_key_exchange(*peer_keys)

    assert len(classic_shared_secret) == CLASSIC_SECRET_SIZE


def test_pq_encapsulated_secret_is_32_bytes(peer_keys):
    """The ML-KEM-768 post-quantum shared secret must be exactly 32 bytes."""
    _, pq_encapsulated_secret, _ = hybrid_key_exchange(*peer_keys)

    assert len(pq_encapsulated_secret) == PQ_SECRET_SIZE


def test_combined_shared_secret_is_64_bytes(peer_keys):
    """The combined shared secret must be 64 bytes (32 classic + 32 post-quantum)."""
    _, _, combined_shared_secret = hybrid_key_exchange(*peer_keys)

    assert len(combined_shared_secret) == COMBINED_SECRET_SIZE


def test_combined_secret_is_classic_concatenated_with_pq(peer_keys):
    """The combined secret must be classic || pq in this exact order."""
    classic_shared_secret, pq_encapsulated_secret, combined_shared_secret = (
        hybrid_key_exchange(*peer_keys)
    )

    assert combined_shared_secret == classic_shared_secret + pq_encapsulated_secret


def test_consecutive_calls_yield_fresh_secrets(peer_keys):
    """Fresh ephemeral keys per call must yield different secrets each time."""
    first = hybrid_key_exchange(*peer_keys)
    second = hybrid_key_exchange(*peer_keys)

    assert first != second


def test_none_x25519_public_key_raises_value_error(peer_keys):
    """Passing None as the X25519 public key must raise ValueError."""
    ml_kem_public_key, _ = peer_keys

    with pytest.raises(ValueError, match="X25519 public key must be bytes"):
        hybrid_key_exchange(ml_kem_public_key, None)


def test_none_ml_kem_public_key_raises_value_error(peer_keys):
    """Passing None as the ML-KEM-768 public key must raise ValueError."""
    _, x25519_public_key = peer_keys

    with pytest.raises(ValueError, match="ML-KEM-768 public key must be bytes"):
        hybrid_key_exchange(None, x25519_public_key)


def test_empty_x25519_public_key_raises_value_error(peer_keys):
    """Passing empty bytes as the X25519 public key must raise ValueError."""
    ml_kem_public_key, _ = peer_keys

    with pytest.raises(ValueError, match="X25519 public key"):
        hybrid_key_exchange(ml_kem_public_key, b"")


def test_empty_ml_kem_public_key_raises_value_error(peer_keys):
    """Passing empty bytes as the ML-KEM-768 public key must raise ValueError."""
    _, x25519_public_key = peer_keys

    with pytest.raises(ValueError, match="ML-KEM-768 public key"):
        hybrid_key_exchange(b"", x25519_public_key)


@pytest.mark.parametrize(
    "bad_key",
    [b"\x00" * 16, b"\x00" * 31, b"\x00" * 33],
    ids=["16B", "31B", "33B"],
)
def test_invalid_size_x25519_public_key_raises_value_error(peer_keys, bad_key):
    """Wrong-size X25519 public keys must raise ValueError."""
    ml_kem_public_key, _ = peer_keys

    with pytest.raises(ValueError, match="X25519 public key"):
        hybrid_key_exchange(ml_kem_public_key, bad_key)


@pytest.mark.parametrize(
    "bad_key",
    [b"\x00" * 100, b"\x00" * 1183, b"\x00" * 1185],
    ids=["100B", "1183B", "1185B"],
)
def test_invalid_size_ml_kem_public_key_raises_value_error(peer_keys, bad_key):
    """Wrong-size ML-KEM-768 public keys must raise ValueError."""
    _, x25519_public_key = peer_keys

    with pytest.raises(ValueError, match="ML-KEM-768 public key"):
        hybrid_key_exchange(bad_key, x25519_public_key)


def test_low_order_x25519_point_raises_value_error(peer_keys):
    """An all-zero low-order X25519 public key must raise ValueError."""
    ml_kem_public_key, _ = peer_keys

    with pytest.raises(ValueError, match="X25519 key exchange failed"):
        hybrid_key_exchange(ml_kem_public_key, b"\x00" * 32)


def test_mocked_pq_secret_flows_into_return_values(peer_keys):
    """A mocked ML-KEM secret must feed the PQ output and the combined secret."""
    ml_kem_public_key, x25519_public_key = peer_keys
    fake_pq_secret = b"\x5a" * 32
    fake_ciphertext = b"\x00" * 1088

    with patch(
        "src.core.ml_kem_encapsulate",
        return_value=(fake_pq_secret, fake_ciphertext),
    ) as mock_encapsulate:
        classic, pq, combined = hybrid_key_exchange(
            ml_kem_public_key, x25519_public_key
        )

    mock_encapsulate.assert_called_once_with(ml_kem_public_key)
    assert pq == fake_pq_secret
    assert combined == classic + fake_pq_secret


def test_local_ml_kem_key_pair_is_generated(peer_keys):
    """The exchange generates a fresh local ML-KEM-768 key pair on each call."""
    ml_kem_public_key, x25519_public_key = peer_keys
    fake_key_pair = (b"\x00" * 1184, b"\x00" * 2400)

    with patch("src.core.ml_kem_keygen", return_value=fake_key_pair) as mock_keygen:
        hybrid_key_exchange(ml_kem_public_key, x25519_public_key)

    mock_keygen.assert_called_once_with()


def test_ml_kem_failure_surfaces_as_value_error(peer_keys):
    """An ML-KEM-768 encapsulation failure must be re-raised as ValueError."""
    ml_kem_public_key, x25519_public_key = peer_keys

    with (
        patch("src.core.ml_kem_encapsulate", side_effect=RuntimeError("boom")),
        pytest.raises(ValueError, match="ML-KEM-768 encapsulation failed"),
    ):
        hybrid_key_exchange(ml_kem_public_key, x25519_public_key)


def test_derive_aes_key_output_is_32_bytes():
    """A valid 64-byte shared secret must derive a 32-byte AES-256 key."""
    aes_key = derive_aes_key(SAMPLE_SHARED_SECRET)

    assert isinstance(aes_key, bytes)
    assert len(aes_key) == AES_KEY_SIZE


def test_derive_aes_key_is_deterministic():
    """The same 64-byte shared secret must always derive the same 32-byte key."""
    first = derive_aes_key(SAMPLE_SHARED_SECRET)
    second = derive_aes_key(SAMPLE_SHARED_SECRET)

    assert first == second


def test_derive_aes_key_differs_for_different_inputs():
    """Different 64-byte shared secrets must derive different AES keys."""
    first = derive_aes_key(SAMPLE_SHARED_SECRET)
    second = derive_aes_key(ALTERNATE_SHARED_SECRET)

    assert first != second


def test_derive_aes_key_rejects_63_byte_input():
    """A 63-byte shared secret (one byte short) must raise ValueError."""
    with pytest.raises(ValueError, match="64 bytes"):
        derive_aes_key(b"\x00" * 63)


def test_derive_aes_key_rejects_65_byte_input():
    """A 65-byte shared secret (one byte too long) must raise ValueError."""
    with pytest.raises(ValueError, match="64 bytes"):
        derive_aes_key(b"\x00" * 65)


def test_derive_aes_key_rejects_empty_input():
    """An empty bytes shared secret must raise ValueError."""
    with pytest.raises(ValueError, match="64 bytes"):
        derive_aes_key(b"")


def test_derive_aes_key_rejects_none_input():
    """Passing None as the shared secret must raise ValueError."""
    with pytest.raises(ValueError, match="must be bytes"):
        derive_aes_key(None)
