import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from src.chaotic_csprng import ChaoticCSPRNG

class HybridCipher:
    """Hybrid cipher: Chaos S-Box + AES-256-GCM."""
    
    VERSION = b'\x01'
    
    def encrypt(self, plaintext: bytes, password: str) -> bytes:
        rng = ChaoticCSPRNG(password)
        key, nonce, salt = rng.generate_key(password)
        sbox = rng.generate_sbox()
        
        substituted = bytes([sbox[b] for b in plaintext])
        
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, substituted, None)
        
        return self.VERSION + salt + nonce + ciphertext
    
    def decrypt(self, data: bytes, password: str) -> bytes:
        if data[0:1] != self.VERSION:
            raise ValueError("Invalid data format")
        
        salt = data[1:33]
        nonce = data[33:45]
        ciphertext = data[45:]
        
        rng = ChaoticCSPRNG(password)
        key, _, _ = rng.generate_key(password, salt)
        sbox = rng.generate_sbox()
        
        inverse_sbox = [0] * 256
        for i, v in enumerate(sbox):
            inverse_sbox[v] = i
        
        aesgcm = AESGCM(key)
        try:
            substituted = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Wrong password or corrupted data")
        
        plaintext = bytes([inverse_sbox[b] for b in substituted])
        return plaintext
    
    def encrypt_file(self, input_path: str, password: str, output_path: str):
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        ciphertext = self.encrypt(plaintext, password)
        with open(output_path, 'wb') as f:
            f.write(ciphertext)
    
    def decrypt_file(self, input_path: str, password: str, output_path: str):
        with open(input_path, 'rb') as f:
            ciphertext = f.read()
        plaintext = self.decrypt(ciphertext, password)
        with open(output_path, 'wb') as f:
            f.write(plaintext)
