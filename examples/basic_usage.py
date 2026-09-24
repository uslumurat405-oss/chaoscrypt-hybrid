"""
ChaosCrypt-Hybrid — basic usage example.

Demonstrates the core functionality of the ChaosCrypt-Hybrid encryption engine:

1. Post-quantum key generation with ML-KEM-768 (NIST FIPS 203).
2. Hybrid encryption: a fresh Lorenz-attractor chaos key is mixed with the
   ML-KEM shared secret to derive an AES-256-GCM key that encrypts the message.
3. Hybrid decryption using the recipient's private key.
4. Tamper detection: a modified packet is rejected by the GCM tag check.

Run from the project root:

    python examples/basic_usage.py

Note: this is a research prototype. See SECURITY.md and THREAT_MODEL.md in the
project root for the security policy and known limitations.
"""

import sys
from pathlib import Path

# Make the project root importable so that "from src.crypto_engine import ..."
# works when this file is executed directly (python examples/basic_usage.py).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.crypto_engine import (
    generate_kyber_keys,
    hybrid_decrypt,
    hybrid_encrypt,
)


def main() -> None:
    """Run the key generation, encryption, decryption, and tamper demo."""
    message = "ChaosCrypt-Hybrid: post-quantum + chaos hybrid encryption demo."
    plaintext = message.encode("utf-8")

    print("=" * 70)
    print("ChaosCrypt-Hybrid - basic usage example")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Step 1: Key generation (ML-KEM-768, NIST FIPS 203)
    # ------------------------------------------------------------------
    # The recipient owns this key pair. The public key is shared with
    # senders; the private key must be kept secret and never transmitted.
    print("\n[1] Generating ML-KEM-768 key pair ...")
    public_key, private_key = generate_kyber_keys()
    print(f"    Public key : {len(public_key)} bytes")
    print(f"    Private key: {len(private_key)} bytes  (keep this secret)")

    # ------------------------------------------------------------------
    # Step 2: Hybrid encryption (ML-KEM-768 + Lorenz chaos key + AES-256-GCM)
    # ------------------------------------------------------------------
    # hybrid_encrypt() performs, in order:
    #   a) a fresh 256-bit chaos seed from the OS CSPRNG (secrets.token_bytes);
    #   b) ML-KEM-768 encapsulation against the recipient's public key;
    #   c) key derivation: SHA3-256(ML-KEM shared secret || chaos key);
    #   d) authenticated encryption with AES-256-GCM.
    # The returned packet is a dict and can be serialized (base64/JSON) for
    # transport over an untrusted channel.
    print("\n[2] Encrypting the message ...")
    packet = hybrid_encrypt(plaintext, public_key)
    print(f"    Plaintext        : {message}")
    print(f"    Ciphertext + tag : {len(packet['ciphertext'])} bytes")
    print(f"    GCM nonce        : {len(packet['nonce'])} bytes")
    print(f"    ML-KEM ciphertext: {len(packet['kyber_ciphertext'])} bytes")
    print(f"    Chaos seed       : {len(packet['chaos_seed'])} bytes")

    # ------------------------------------------------------------------
    # Step 3: Decryption with the recipient's private key
    # ------------------------------------------------------------------
    # hybrid_decrypt() re-derives the same AES key via ML-KEM decapsulation
    # and Lorenz chaos key regeneration, then verifies the GCM authentication
    # tag in constant time (hmac.compare_digest). A wrong key or a corrupted
    # packet raises ValueError instead of returning corrupted plaintext.
    print("\n[3] Decrypting the packet ...")
    decrypted = hybrid_decrypt(packet, private_key)
    recovered = decrypted.decode("utf-8")
    print(f"    Recovered        : {recovered}")

    if recovered != message:
        raise SystemExit("Round-trip mismatch: decryption failed.")
    print("    Result           : OK - decrypted text matches the original.")

    # ------------------------------------------------------------------
    # Step 4: Tamper detection (AES-256-GCM authentication)
    # ------------------------------------------------------------------
    # Flip one bit of the ciphertext; the GCM tag check must reject it.
    print("\n[4] Tamper detection check ...")
    tampered = dict(packet)
    corrupted = bytearray(tampered["ciphertext"])
    corrupted[0] ^= 0x01
    tampered["ciphertext"] = bytes(corrupted)
    try:
        hybrid_decrypt(tampered, private_key)
        print("    ERROR: tampered packet was accepted!")
    except ValueError as exc:
        print(f"    Tampered packet rejected as expected ({exc}).")

    print("\nDone.")


if __name__ == "__main__":
    main()
