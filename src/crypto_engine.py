import hashlib

import numpy as np


def generate_chaos_key(seed: bytes, iterations: int = 10000) -> bytes:
    """
    Lorenz attractor kullanarak 256-bit şifreleme anahtarı üretir.

    Args:
        seed: 24 byte'lık başlangıç değeri (3x float64)
        iterations: Lorenz iterasyon sayısı (default: 10000)

    Returns:
        32 byte'lık SHA3-256 hash'lenmiş anahtar
    """
    if len(seed) != 24:
        raise ValueError("seed must be exactly 24 bytes")

    x, y, z = np.frombuffer(seed, dtype=np.float64)

    sigma = 10.0
    rho = 28.0
    beta = 8.0 / 3.0
    dt = 0.01

    for _ in range(iterations):
        dx = sigma * (y - x)
        dy = x * (rho - z) - y
        dz = x * y - beta * z
        x = x + dt * dx
        y = y + dt * dy
        z = z + dt * dz

    final_state = np.array([x, y, z], dtype=np.float64)
    state_bytes = final_state.tobytes()

    return hashlib.sha3_256(state_bytes).digest()
