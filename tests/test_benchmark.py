"""ChaosCrypt çekirdek kriptografik işlemleri için performans benchmark testleri.

Her işlem ısıtma (warmup) turlarından sonra ``time.perf_counter_ns()`` ile
ölçülür; işlem başına ortalama / minimum / maksimum süre, standart sapma,
toplam süre ve saniye başına işlem sayısı raporlanır.

Sonuçlar kabul edilebilir eşiklerle (``ACCEPTABLE_THRESHOLDS_MS``) karşılaştırılır
ve Fast / Medium / Slow olarak derecelendirilir:

- Fast   : ortalama <= eşiğin %50'si
- Medium : ortalama <= eşik
- Slow   : ortalama > eşik (performans regresyonu; test hatası üretir)

Özet raporu (``test_summary_report``) tüm benchmark'ları tek tabloda eşiklerle
karşılaştırır ve tam hibrit şifreleme/çözme döngüsünün toplam süresini verir.

Çalıştırma: ``python -m pytest tests/test_benchmark.py -v -s``
"""

import gc
import os
import statistics
import time
from dataclasses import dataclass
from typing import Callable

from Crypto.Cipher import AES

from src.crypto_engine import (
    constant_time_equal,
    generate_chaos_key,
    hybrid_decrypt,
    hybrid_encrypt,
    ml_kem_decapsulate,
    ml_kem_encapsulate,
    ml_kem_keygen,
)

# ---------------------------------------------------------------------------
# Benchmark yapılandırması
# ---------------------------------------------------------------------------

ML_KEM_KEYGEN_ITERATIONS = 100
ML_KEM_ENCAPSULATION_ITERATIONS = 100
ML_KEM_DECAPSULATION_ITERATIONS = 100
AES_DATA_SIZE = 1024 * 1024  # 1 MiB düz metin
AES_ITERATIONS = 100
CHAOS_KEY_ITERATIONS = 100
HYBRID_CYCLE_ITERATIONS = 10
WARMUP_ITERATIONS = 3
MIB = 1024 * 1024

# Kabul edilebilir eşikler: işlem başına ortalama süre üst sınırı (ms).
# Değerler bu makinedeki ölçümlere göre ~4-10x pay bırakacak şekilde
# "kabul edilebilir" performansı tanımlar; aşan (Slow) sonuç test hatasıdır.
ACCEPTABLE_THRESHOLDS_MS = {
    "ML-KEM-768 key generation": 1.0,
    "ML-KEM-768 encapsulation": 1.0,
    "ML-KEM-768 decapsulation": 1.0,
    "AES-256-GCM encryption (1MB)": 10.0,
    "Lorenz key generation": 400.0,
    "Hybrid encrypt/decrypt cycle": 1000.0,
}


@dataclass
class BenchmarkResult:
    """Tek bir benchmark'ın ölçüm sonuçları."""

    name: str
    iterations: int
    times_ms: list[float]
    data_size: int = 0  # işlenen bayt sayısı (verim hesabı için)

    @property
    def avg_ms(self) -> float:
        return statistics.mean(self.times_ms)

    @property
    def min_ms(self) -> float:
        return min(self.times_ms)

    @property
    def max_ms(self) -> float:
        return max(self.times_ms)

    @property
    def stdev_ms(self) -> float:
        return statistics.stdev(self.times_ms) if len(self.times_ms) > 1 else 0.0

    @property
    def total_ms(self) -> float:
        return sum(self.times_ms)

    @property
    def ops_per_sec(self) -> float:
        return self.iterations / (self.total_ms / 1000.0)

    @property
    def throughput_mib_per_sec(self) -> float:
        """Veri boyutu bilinen işlemler için MiB/s verim."""
        if self.data_size <= 0 or self.avg_ms <= 0:
            return 0.0
        return (self.data_size / MIB) / (self.avg_ms / 1000.0)

    @property
    def threshold_ms(self) -> float:
        return ACCEPTABLE_THRESHOLDS_MS[self.name]

    @property
    def rating(self) -> str:
        return performance_rating(self.avg_ms, self.threshold_ms)


# Özet rapor, test tanım sırasıyla bu sözlükleri doldurur.
BENCHMARK_RESULTS: dict[str, BenchmarkResult] = {}
CYCLE_DETAILS: dict[str, float] = {}


# ---------------------------------------------------------------------------
# Ölçüm ve raporlama yardımcıları
# ---------------------------------------------------------------------------


def performance_rating(avg_ms: float, threshold_ms: float) -> str:
    """Ortalama süreyi eşiğe göre Fast / Medium / Slow olarak derecelendirir."""
    ratio = avg_ms / threshold_ms
    if ratio <= 0.5:
        return "Fast"
    if ratio <= 1.0:
        return "Medium"
    return "Slow"


def run_benchmark(
    name: str,
    func: Callable[[], object],
    iterations: int,
    data_size: int = 0,
    warmup: int = WARMUP_ITERATIONS,
) -> BenchmarkResult:
    """`func`'i warmup sonrası `iterations` kez ölçer; sonuçları ns hassasiyetle toplar."""
    for _ in range(warmup):
        func()

    times_ms: list[float] = []
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(iterations):
            start = time.perf_counter_ns()
            func()
            times_ms.append((time.perf_counter_ns() - start) / 1e6)
    finally:
        if gc_was_enabled:
            gc.enable()

    return BenchmarkResult(name=name, iterations=iterations, times_ms=times_ms, data_size=data_size)


def format_result(result: BenchmarkResult) -> str:
    """Tek bir benchmark sonucunu biçimlendirilmiş blok olarak döndürür."""
    lines = [
        "",
        f"{result.name} ({result.iterations} iterations)",
        "-" * 60,
        f"  Average   : {result.avg_ms:12.3f} ms",
        f"  Min       : {result.min_ms:12.3f} ms",
        f"  Max       : {result.max_ms:12.3f} ms",
        f"  Std dev   : {result.stdev_ms:12.3f} ms",
        f"  Total     : {result.total_ms:12.3f} ms",
        f"  Ops/sec   : {result.ops_per_sec:12.1f}",
    ]
    if result.throughput_mib_per_sec > 0:
        lines.append(f"  Throughput: {result.throughput_mib_per_sec:11.1f} MiB/s")
    lines += [
        f"  Threshold : {result.threshold_ms:12.3f} ms",
        f"  Rating    : {result.rating:>11s}",
    ]
    return "\n".join(lines)


def assert_benchmark_sanity(result: BenchmarkResult) -> None:
    """Ölçüm tutarlılığını ve kabul edilebilir eşiği doğrular (Slow = hata)."""
    assert result.min_ms > 0.0
    assert result.min_ms <= result.avg_ms <= result.max_ms
    assert result.ops_per_sec > 0.0
    assert result.rating != "Slow", (
        f"{result.name} kabul edilebilir eşiği aştı: ortalama {result.avg_ms:.3f} ms > "
        f"eşik {result.threshold_ms:.3f} ms\n{format_result(result)}"
    )


# ---------------------------------------------------------------------------
# Benchmark testleri
# ---------------------------------------------------------------------------


def test_benchmark_ml_kem_keygen():
    """ML-KEM-768 anahtar üretimi (100 iterasyon)."""
    public_key, private_key = ml_kem_keygen()
    assert len(public_key) == 1184 and len(private_key) == 2400

    result = run_benchmark("ML-KEM-768 key generation", ml_kem_keygen, ML_KEM_KEYGEN_ITERATIONS)
    BENCHMARK_RESULTS[result.name] = result

    print(format_result(result))
    assert_benchmark_sanity(result)


def test_benchmark_ml_kem_encapsulation():
    """ML-KEM-768 encapsulation (100 iterasyon)."""
    public_key, private_key = ml_kem_keygen()
    shared_secret, ciphertext = ml_kem_encapsulate(public_key)
    assert len(ciphertext) == 1088 and len(shared_secret) == 32
    assert constant_time_equal(ml_kem_decapsulate(private_key, ciphertext), shared_secret)

    result = run_benchmark(
        "ML-KEM-768 encapsulation",
        lambda: ml_kem_encapsulate(public_key),
        ML_KEM_ENCAPSULATION_ITERATIONS,
    )
    BENCHMARK_RESULTS[result.name] = result

    print(format_result(result))
    assert_benchmark_sanity(result)


def test_benchmark_ml_kem_decapsulation():
    """ML-KEM-768 decapsulation (100 iterasyon)."""
    public_key, private_key = ml_kem_keygen()
    shared_secret, ciphertext = ml_kem_encapsulate(public_key)
    assert constant_time_equal(ml_kem_decapsulate(private_key, ciphertext), shared_secret)

    result = run_benchmark(
        "ML-KEM-768 decapsulation",
        lambda: ml_kem_decapsulate(private_key, ciphertext),
        ML_KEM_DECAPSULATION_ITERATIONS,
    )
    BENCHMARK_RESULTS[result.name] = result

    print(format_result(result))
    assert_benchmark_sanity(result)


def test_benchmark_aes_256_gcm_encryption():
    """AES-256-GCM ile 1 MiB veri şifreleme (100 iterasyon)."""
    key = os.urandom(32)
    plaintext = os.urandom(AES_DATA_SIZE)

    # Doğruluk ön kontrolü: ölçüm dışında bir gidiş-dönüş.
    nonce = os.urandom(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    assert len(ciphertext) == AES_DATA_SIZE and len(tag) == 16
    verifier = AES.new(key, AES.MODE_GCM, nonce=nonce)
    assert constant_time_equal(verifier.decrypt_and_verify(ciphertext, tag), plaintext)

    def aes_gcm_encrypt_1mib() -> None:
        op_cipher = AES.new(key, AES.MODE_GCM, nonce=os.urandom(12))
        op_cipher.encrypt_and_digest(plaintext)

    result = run_benchmark(
        "AES-256-GCM encryption (1MB)", aes_gcm_encrypt_1mib, AES_ITERATIONS, data_size=AES_DATA_SIZE
    )
    BENCHMARK_RESULTS[result.name] = result

    print(format_result(result))
    assert_benchmark_sanity(result)


def test_benchmark_lorenz_key_generation():
    """Lorenz kaotik anahtar türetimi (100 iterasyon, her çağrıda 10.000 Lorenz adımı)."""
    seed = os.urandom(32)
    assert constant_time_equal(generate_chaos_key(seed), generate_chaos_key(seed))
    assert len(generate_chaos_key()) == 32

    result = run_benchmark("Lorenz key generation", generate_chaos_key, CHAOS_KEY_ITERATIONS)
    BENCHMARK_RESULTS[result.name] = result

    print(format_result(result))
    assert_benchmark_sanity(result)


def test_benchmark_hybrid_encryption_decryption_cycle():
    """Tam hibrit şifreleme + çözme döngüsü (10 iterasyon, 1 MiB düz metin)."""
    public_key, private_key = ml_kem_keygen()
    plaintext = os.urandom(AES_DATA_SIZE)

    # Doğruluk ön kontrolü.
    encrypted = hybrid_encrypt(plaintext, public_key)
    assert constant_time_equal(hybrid_decrypt(encrypted, private_key), plaintext)

    encrypt_times_ms: list[float] = []
    decrypt_times_ms: list[float] = []
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(WARMUP_ITERATIONS):
            hybrid_decrypt(hybrid_encrypt(plaintext, public_key), private_key)

        for _ in range(HYBRID_CYCLE_ITERATIONS):
            start = time.perf_counter_ns()
            encrypted = hybrid_encrypt(plaintext, public_key)
            mid = time.perf_counter_ns()
            decrypted = hybrid_decrypt(encrypted, private_key)
            end = time.perf_counter_ns()
            assert constant_time_equal(decrypted, plaintext)
            encrypt_times_ms.append((mid - start) / 1e6)
            decrypt_times_ms.append((end - mid) / 1e6)
    finally:
        if gc_was_enabled:
            gc.enable()

    cycle_times = [e + d for e, d in zip(encrypt_times_ms, decrypt_times_ms)]
    result = BenchmarkResult(
        name="Hybrid encrypt/decrypt cycle",
        iterations=HYBRID_CYCLE_ITERATIONS,
        times_ms=cycle_times,
        data_size=AES_DATA_SIZE,
    )
    BENCHMARK_RESULTS[result.name] = result
    CYCLE_DETAILS.update(
        encrypt_avg_ms=statistics.mean(encrypt_times_ms),
        decrypt_avg_ms=statistics.mean(decrypt_times_ms),
        total_cycles_ms=result.total_ms,
    )

    print(format_result(result))
    print(
        f"  Breakdown : encrypt {CYCLE_DETAILS['encrypt_avg_ms']:10.3f} ms avg | "
        f"decrypt {CYCLE_DETAILS['decrypt_avg_ms']:10.3f} ms avg"
    )
    assert_benchmark_sanity(result)


def test_summary_report():
    """Tüm benchmark sonuçlarını eşiklerle karşılaştıran özet performans raporu."""
    missing = [name for name in ACCEPTABLE_THRESHOLDS_MS if name not in BENCHMARK_RESULTS]
    assert not missing, f"eksik benchmark sonuçları: {missing}"

    width = 94
    lines = [
        "",
        "=" * width,
        "ChaosCrypt Performance Benchmark Summary".center(width),
        "=" * width,
        f"{'Operation':30s} {'Avg (ms)':>10s} {'Min (ms)':>10s} {'Max (ms)':>10s} "
        f"{'Ops/sec':>10s} {'Thr (ms)':>10s} {'Rating':>8s}",
        "-" * width,
    ]

    ratings: list[str] = []
    for name in ACCEPTABLE_THRESHOLDS_MS:
        result = BENCHMARK_RESULTS[name]
        ratings.append(result.rating)
        lines.append(
            f"{name:30s} {result.avg_ms:10.3f} {result.min_ms:10.3f} {result.max_ms:10.3f} "
            f"{result.ops_per_sec:10.1f} {result.threshold_ms:10.3f} {result.rating:>8s}"
        )

    lines += [
        "-" * width,
        f"Hybrid cycle: {HYBRID_CYCLE_ITERATIONS} full encrypt+decrypt cycles over 1 MiB payload",
        f"  Total time for full cycles : {CYCLE_DETAILS['total_cycles_ms']:10.3f} ms "
        f"({CYCLE_DETAILS['total_cycles_ms'] / 1000.0:.3f} s)",
        f"  Average per cycle          : {CYCLE_DETAILS['total_cycles_ms'] / HYBRID_CYCLE_ITERATIONS:10.3f} ms",
        f"  Breakdown (average)        : encrypt {CYCLE_DETAILS['encrypt_avg_ms']:10.3f} ms | "
        f"decrypt {CYCLE_DETAILS['decrypt_avg_ms']:10.3f} ms",
    ]

    fast = sum(1 for r in ratings if r == "Fast")
    medium = sum(1 for r in ratings if r == "Medium")
    slow = sum(1 for r in ratings if r == "Slow")
    verdict = (
        "ALL BENCHMARKS WITHIN ACCEPTABLE THRESHOLDS"
        if slow == 0
        else f"{slow} BENCHMARK(S) EXCEEDED ACCEPTABLE THRESHOLDS"
    )
    lines += [
        "-" * width,
        f"Overall: {fast} Fast / {medium} Medium / {slow} Slow -- {verdict}",
        "=" * width,
    ]

    print("\n".join(lines))
    assert slow == 0, f"{slow} benchmark eşiği aştı; tablodaki Slow satırlarına bakın"
