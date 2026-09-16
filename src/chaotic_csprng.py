import hashlib
import os
from src.chaos_engine import ChaosEngine

class ChaoticCSPRNG:
    """Chaotic Cryptographically Secure Pseudo-Random Number Generator."""
    
    def __init__(self, master_seed: str):
        self.engine = ChaosEngine(master_seed)
    
    def whiten(self, data: bytes) -> bytes:
        """Von Neumann extractor to remove bias from chaotic bytes."""
        bits = []
        for i in range(0, len(data) - 1, 2):
            a, b = data[i], data[i + 1]
            if a > b:
                bits.append(1)
            elif a < b:
                bits.append(0)
        
        out = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            out.append(byte)
        return bytes(out)
    
    def extract_bytes(self, n: int) -> bytes:
        """Generate n high-entropy whitened bytes with de-correlation mixing."""
        pool = bytearray()
        round_num = 0
        while len(pool) < n * 4:
            raw = self.engine.extract_bytes(4096)
            whitened = self.whiten(raw)
            mix = hashlib.sha256(whitened + round_num.to_bytes(4, 'big')).digest()
            for i, byte in enumerate(whitened):
                pool.append(byte ^ mix[i % 32])
            round_num += 1
        
        result = bytearray()
        for i in range(n):
            window = bytes(pool[i:i + 64])
            h = hashlib.sha256(window + i.to_bytes(4, 'big')).digest()
            result.append(h[0] ^ h[7] ^ h[15] ^ h[23] ^ h[31] ^ pool[i % len(pool)])
        return bytes(result)
    
    def generate_key(self, password: str, salt: bytes = None) -> tuple:
        """Generate 32-byte key and 12-byte nonce from password."""
        if salt is None:
            salt = os.urandom(32)
        
        chaotic = self.extract_bytes(1024)
        mix_input = password.encode() + salt + chaotic
        key = hashlib.pbkdf2_hmac(
            'sha256',
            mix_input,
            salt,
            100000,
            dklen=32
        )
        
        nonce_material = self.extract_bytes(64) + os.urandom(16)
        nonce = hashlib.sha256(nonce_material).digest()[:12]
        
        return key, nonce, salt
    
    def generate_sbox(self) -> list:
        """Generate a dynamic 256-byte substitution box from chaos."""
        sbox = list(range(256))
        
        for pass_num in range(4):
            raw = self.extract_bytes(512)
            for i in range(255, 0, -1):
                j = (raw[i % len(raw)] ^ raw[(255 - i) % len(raw)] ^ pass_num) % (i + 1)
                sbox[i], sbox[j] = sbox[j], sbox[i]
        
        return sbox
    
    def entropy_check(self, data: bytes) -> float:
        """Calculate Shannon entropy (max 8.0 for 8-bit data)."""
        if not data:
            return 0.0
        
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        length = len(data)
        for count in freq:
            if count > 0:
                p = count / length
                entropy -= p * (p and __import__('math').log2(p))
        
        return entropy
