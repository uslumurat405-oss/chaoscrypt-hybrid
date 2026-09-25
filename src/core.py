"""
ChaosCrypt-Hybrid — core hybrid key exchange.

Combines the classical X25519 (RFC 7748) ECDH key exchange with the
post-quantum ML-KEM-768 (NIST FIPS 203) key encapsulation mechanism so that
the resulting shared secret stays secure as long as at least one of the two
algorithms remains unbroken.
"""

import ctypes
from types import TracebackType
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.crypto_engine import ml_kem_encapsulate, ml_kem_keygen

X25519_PUBLIC_KEY_SIZE = 32
ML_KEM_PUBLIC_KEY_SIZE = 1184
SHARED_SECRET_SIZE = 32
COMBINED_SECRET_SIZE = 64
AES_KEY_SIZE = 32
HKDF_INFO = b"chaoscrypt-v1-aes-key"


def hybrid_key_exchange(
    peer_ml_kem_public_key: bytes,
    peer_x25519_public_key: bytes,
) -> Tuple[bytes, bytes, bytes]:
    """
    Hybrid key exchange: X25519 (classical) + ML-KEM-768 (post-quantum).

    A fresh local X25519 key pair is generated and combined with the peer's
    X25519 public key through ECDH to obtain the classical shared secret.
    A fresh local ML-KEM-768 key pair is generated as well, and a
    post-quantum shared secret is produced by ML-KEM-768 encapsulation
    against the peer's ML-KEM-768 public key. Both secrets are concatenated
    (classic || pq) to form the combined shared secret.

    Args:
        peer_ml_kem_public_key: Peer's ML-KEM-768 public key (1184 bytes).
        peer_x25519_public_key: Peer's X25519 public key (32 bytes).

    Returns:
        Tuple of (classic_shared_secret, pq_encapsulated_secret,
        combined_shared_secret):

        - classic_shared_secret: 32-byte X25519 ECDH shared secret.
        - pq_encapsulated_secret: 32-byte ML-KEM-768 shared secret.
        - combined_shared_secret: 64-byte concatenation (classic || pq).

    Raises:
        ValueError: If either peer key is not bytes or does not have the
            expected length, or if the X25519 key exchange or ML-KEM-768
            encapsulation fails.
    """
    if not isinstance(peer_x25519_public_key, bytes):
        raise ValueError("peer X25519 public key must be bytes")
    if not isinstance(peer_ml_kem_public_key, bytes):
        raise ValueError("peer ML-KEM-768 public key must be bytes")
    if len(peer_x25519_public_key) != X25519_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"peer X25519 public key must be {X25519_PUBLIC_KEY_SIZE} bytes"
        )
    if len(peer_ml_kem_public_key) != ML_KEM_PUBLIC_KEY_SIZE:
        raise ValueError(
            f"peer ML-KEM-768 public key must be {ML_KEM_PUBLIC_KEY_SIZE} bytes"
        )

    # Classical half: generate an ephemeral local X25519 key pair and perform
    # ECDH with the peer's X25519 public key.
    try:
        local_x25519_private_key = X25519PrivateKey.generate()
        peer_x25519_key = X25519PublicKey.from_public_bytes(peer_x25519_public_key)
        classic_shared_secret = local_x25519_private_key.exchange(peer_x25519_key)
    except Exception as exc:
        raise ValueError(f"X25519 key exchange failed: {exc}") from exc
    if len(classic_shared_secret) != SHARED_SECRET_SIZE:
        raise ValueError(
            f"X25519 shared secret must be {SHARED_SECRET_SIZE} bytes"
        )

    # Post-quantum half: generate a local ML-KEM-768 key pair and perform
    # encapsulation against the peer's public key.
    try:
        _local_ml_kem_public_key, _local_ml_kem_private_key = ml_kem_keygen()
        pq_encapsulated_secret, _pq_ciphertext = ml_kem_encapsulate(
            peer_ml_kem_public_key
        )
    except Exception as exc:
        raise ValueError(f"ML-KEM-768 encapsulation failed: {exc}") from exc
    if len(pq_encapsulated_secret) != SHARED_SECRET_SIZE:
        raise ValueError(
            f"ML-KEM-768 shared secret must be {SHARED_SECRET_SIZE} bytes"
        )

    combined_shared_secret = classic_shared_secret + pq_encapsulated_secret
    return classic_shared_secret, pq_encapsulated_secret, combined_shared_secret


def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derive a 32-byte AES-256 key from the 64-byte hybrid shared secret.

    Runs HKDF-SHA256 (RFC 5869) with no salt and the fixed info string
    b"chaoscrypt-v1-aes-key", so a given shared secret always maps to the
    same AES key while unrelated secrets map to unrelated keys.

    Args:
        shared_secret: 64-byte combined shared secret (classic || pq)
            produced by hybrid_key_exchange().

    Returns:
        32-byte AES-256 encryption key.

    Raises:
        ValueError: If shared_secret is not bytes or is not exactly 64 bytes.
    """
    if not isinstance(shared_secret, bytes):
        raise ValueError("shared_secret must be bytes")
    if len(shared_secret) != COMBINED_SECRET_SIZE:
        raise ValueError(
            f"shared_secret must be {COMBINED_SECRET_SIZE} bytes"
        )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=HKDF_INFO,
    )
    return hkdf.derive(shared_secret)


def secure_wipe(data: bytearray) -> None:
    """
    Overwrite a mutable buffer with zeros, in place.

    The zeroing is performed by the C library's ``memset`` through
    ``ctypes`` on a buffer view that shares the bytearray's memory, so the
    write lands directly in the original buffer. An explicit wipe matters
    because CPython's garbage collector does not scrub memory when objects
    are freed: without it, key material and plaintext remain readable in
    freed heap blocks until the pages are reused.

    Limitations imposed by CPython's memory model:

    - Only ``bytearray`` buffers can be wiped. Immutable ``bytes`` objects
      (the return type of the key-exchange functions in this package)
      cannot be modified after creation; keep sensitive material in
      ``bytearray`` form, or wrap it with ``bytearray(...)`` before wiping.
    - Wiping affects exactly this one buffer. Copies created earlier
      (``bytes(data)``, slices, concatenations, values handed to other
      functions) are independent objects and survive the wipe.
    - A bytearray that was resized during its lifetime may already have
      left stale copies of its former contents in freed heap memory; those
      cannot be erased retroactively.
    - The operating system can hold further copies in the swap/pagefile or
      hibernation files; no in-process wipe can reach those.
    - Wiping is deliberately never tied to ``__del__``: CPython does not
      guarantee when (or whether) finalizers run, so structured cleanup
      (see SensitiveData) is used instead.

    Args:
        data: Mutable buffer whose contents will be zeroed in place.

    Raises:
        ValueError: If data is not a bytearray.
    """
    if not isinstance(data, bytearray):
        raise ValueError("data must be bytearray")
    if not data:
        return
    ctypes.memset((ctypes.c_char * len(data)).from_buffer(data), 0, len(data))


def secure_wipe_dict(data: dict) -> None:
    """
    Zero every bytearray value stored in a dictionary, in place.

    Intended for result/packet mappings that carry secret material
    (hybrid keys, shared secrets, plaintext). Top-level values that are
    ``bytearray`` instances are wiped via secure_wipe(); values of any
    other type — including immutable ``bytes``, which cannot be wiped — are
    left untouched, and nested containers (dicts, lists, tuples) are not
    traversed.

    See secure_wipe() for the CPython-level limitations of memory wiping
    (surviving copies, freed blocks, swap files).

    Args:
        data: Dictionary whose bytearray values will be zeroed in place.

    Raises:
        ValueError: If data is not a dict.
    """
    if not isinstance(data, dict):
        raise ValueError("data must be dict")
    for value in data.values():
        if isinstance(value, bytearray):
            secure_wipe(value)


class SensitiveData:
    """
    Context manager that wipes all bytearray values of a mapping on exit.

    Holds a reference (not a copy) to the caller's mapping, so the wipe
    zeroes the original buffers. Intended for scoped handling of key
    material and plaintext:

        with SensitiveData(
            {"aes_key": bytearray(aes_key), "plaintext": bytearray(pt)}
        ) as sensitive:
            aes_key = sensitive["aes_key"]
            ...  # use the material
        # every bytearray value is zeroed here, even if the block raised

    Exceptions raised inside the managed block are never suppressed; the
    buffers are wiped on the way out either way (finally-style semantics).

    Limitations: values of other types and nested containers are not wiped
    (see secure_wipe_dict()), and the same CPython constraints as
    secure_wipe() apply — copies made before the wipe, remnants of resized
    buffers, and OS-level copies (swap/pagefile) cannot be erased. Wiping is
    tied to ``__exit__`` instead of ``__del__`` because CPython does not
    guarantee finalizer execution.
    """

    def __init__(self, data: dict) -> None:
        """
        Wrap a mapping of named sensitive buffers.

        The mapping is expected to hold bytearray values; other value types
        are tolerated but are never wiped.

        Args:
            data: Mapping whose bytearray values will be zeroed on exit.

        Raises:
            ValueError: If data is not a dict.
        """
        if not isinstance(data, dict):
            raise ValueError("data must be dict")
        self._data = data

    def __enter__(self) -> "SensitiveData":
        """Return self so the managed block can access the buffers."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """
        Wipe every bytearray value in the wrapped mapping.

        Runs whether the managed block completed normally or raised;
        returns None so exceptions are never suppressed.
        """
        secure_wipe_dict(self._data)

    def __getitem__(self, key: str) -> bytearray:
        """Return the buffer stored under key."""
        return self._data[key]
