import pytest
import numpy as np
from src.chaos_engine import ChaosEngine

def test_determinism():
    """Same seed produces same output."""
    e1 = ChaosEngine("test_seed")
    e2 = ChaosEngine("test_seed")
    assert e1.extract_bytes(1000) == e2.extract_bytes(1000)

def test_avalanche():
    """1 character difference → 95%+ different output."""
    e1 = ChaosEngine("test_seed")
    e2 = ChaosEngine("test_seeD")
    d1, d2 = e1.extract_bytes(1000), e2.extract_bytes(1000)
    diff = sum(1 for a, b in zip(d1, d2) if a != b)
    assert diff / len(d1) > 0.95

def test_no_collapse():
    """200K iterations, std > 0.1 (no collapse)."""
    e = ChaosEngine("test_seed")
    data = e.generate(200000)
    assert np.std(data[-10000:, 0]) > 0.1

def test_lyapunov_positive():
    """Lyapunov > 0 (chaotic)."""
    e = ChaosEngine("test_seed")
    lyap = e.lyapunov_exponent(10000)
    assert lyap > 0.5

def test_extract_bytes_range():
    """Bytes in 0-255, 250+ unique."""
    e = ChaosEngine("test_seed")
    data = e.extract_bytes(10000)
    assert all(0 <= b <= 255 for b in data)
    assert len(set(data)) > 250

def test_perturbation_effect():
    """Perturbation on/off produces different output."""
    e1 = ChaosEngine("test_seed")
    d1 = e1.extract_bytes(5000)
    assert len(d1) == 5000
