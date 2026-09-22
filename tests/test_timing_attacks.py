"""Zamanlama yan kanalı (timing side-channel) savunmalarının testleri.

`hmac.compare_digest` tabanlı sabit zamanlı karşılaştırmaların, farklılığın
bayt konumundan bağımsız olarak benzer sürede tamamlandığını ve hybrid
decrypt yolundaki tag doğrulamasının kurcalanmış paketleri reddettiğini
doğrular.
"""

import gc
import hmac
import statistics
import time
from pathlib import Path

import pytest

from src.crypto_engine import (
    GCM_TAG_SIZE,
    constant_time_equal,
    generate_kyber_keys,
    hybrid_decrypt,
    hybrid_encrypt,
    ml_kem_decapsulate,
    ml_kem_encapsulate,
    ml_kem_keygen,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]

ITERATIONS = 10_000
WARMUP_ITERATIONS = 1_000
ACCEPTABLE_VARIANCE = 0.05  # senaryolar arası kabul edilebilir göreli sapma
KEM_DECAPS_ITERATIONS = 1_000
KEM_DECAPS_ACCEPTABLE_VARIANCE = 0.10
BUFFER_COPY_COUNT = 32  # bellek yerleşim gürültüsünü ortalamak için senaryo başına kopya sayısı
# Zamanlayıcı çözünürlüğünün (QPC ~100ns) altındaki karşılaştırmalar için her
# ölçüm penceresinde tekrarlanan karşılaştırma sayısı: hem kuantalanmayı hem
# pencere başı cache etkilerini ortadan kaldırır, gerçek value-dependent erken
# çıkışı ise pencere içinde toplayarak güçlendirir.
COMPARISON_BATCH_SIZE = 64

PLAINTEXT = b"timing side-channel resistant payload"


def _first_byte_flipped(data: bytes) -> bytes:
    """İlk baytı 1 bit farklı olan kopya üretir."""
    return bytes([data[0] ^ 0x01]) + data[1:]


def _last_byte_flipped(data: bytes) -> bytes:
    """Son baytı 1 bit farklı olan kopya üretir."""
    return data[:-1] + bytes([data[-1] ^ 0x01])


def _timed_samples(
    comparison, a, variants, iterations=ITERATIONS, warmup=WARMUP_ITERATIONS,
    copies=BUFFER_COPY_COUNT, batch=1,
):
    """
    `variants` (isim -> bayt dizisi) ile `a`'yı kesişmeli (interleaved) ölçer.

    Her senaryo için `copies` adet (a_kopyası, b_kopyası) çifti üretilir; her
    çiftte a_kopyası hemen b_kopyasından önce ayrılır ve çiftler senaryolar
    arasında dönüşümlü üretilir. Böylece tüm karşılaştırmalar aynı bellek
    komşuluk yapısını örnekler ve cache hizalanması kaynaklı sabit yanlılık
    senaryolar arasında eşitlenir. Senaryo sırası her turda kaydırılır
    (rotasyon). Ölçüm `time.perf_counter_ns()` ile yapılır; `batch` > 1 ise her
    pencere içinde aynı karşılaştırma `batch` kez tekrarlanır ve süre karşılaştırma
    başına normalize edilir.
    """
    items = list(variants.items())
    scenario_pairs = {name: [] for name in variants}
    for _ in range(copies):
        for name, b in items:
            a_copy = bytes(a)
            b_copy = bytes(b)
            scenario_pairs[name].append((a_copy, b_copy))

    for _ in range(warmup):  # cache / branch predictor ısınması
        for _, b in items:
            comparison(a, b)

    samples = {name: [] for name in variants}
    gc_was_enabled = gc.isenabled()
    gc.disable()
    try:
        for round_num in range(iterations):
            # Konum yanlılığını dengelemek için senaryo sırasını her turda kaydır.
            shift = round_num % len(items)
            order = items[shift:] + items[:shift]
            pair_index = round_num % copies
            for name, _ in order:
                a_copy, b_copy = scenario_pairs[name][pair_index]
                time.perf_counter_ns()  # ölçüm penceresi öncesi durumu normalize et
                start = time.perf_counter_ns()
                for _ in range(batch):
                    comparison(a_copy, b_copy)
                samples[name].append((time.perf_counter_ns() - start) / batch)
    finally:
        if gc_was_enabled:
            gc.enable()
    return samples


def _timing_stats(samples, trim_fraction=0.02):
    """Süre örneklerinin ortalama, medyan, varyans ve uç değerlerden arındırılmış ortalaması."""
    ordered = sorted(samples)
    trim = max(1, int(len(ordered) * trim_fraction))
    core = ordered[trim:-trim]
    return {
        "count": len(samples),
        "mean": statistics.mean(samples),
        "median": statistics.median(samples),
        "variance": statistics.variance(samples),
        "stdev": statistics.stdev(samples),
        "trimmed_mean": statistics.mean(core),
    }


def _relative_spread(values):
    """Senaryo istatistikleri arası göreli sapma: (max - min) / ortalama."""
    overall = statistics.mean(values)
    if overall <= 0:
        return 0.0
    return (max(values) - min(values)) / overall


def _report(stats_by_scenario):
    """Senaryo başına zamanlama istatistiklerini okunabilir biçimde döndürür."""
    return "\n".join(
        f"  {name}: mean={s['mean']:.1f}ns median={s['median']:.1f}ns "
        f"trimmed_mean={s['trimmed_mean']:.1f}ns variance={s['variance']:.1f}ns2 "
        f"stdev={s['stdev']:.1f}ns (n={s['count']})"
        for name, s in stats_by_scenario.items()
    )


# ---------------------------------------------------------------------------
# Gerekli test: hmac.compare_digest bayt konumundan bağımsız sabit sürede çalışmalı
# ---------------------------------------------------------------------------


def test_constant_time_comparison():
    """
    Sabit zamanlı karşılaştırma: süre farklılığın bayt konumuna bağlı olmamalı.

    Aynı 32 baytlık anahtar malzemesi ile (1) birebir aynı, (2) ilk baytı
    farklı, (3) son baytı farklı karşılaştırmalar 10.000 ölçüm penceresinde
    (zamanlayıcı çözünürlüğünün altındaki süre için pencere başına 64 tekrar)
    ölçülür; senaryolar arası göreli zamanlama sapması %5'in altında
    olmalıdır.
    """
    key = bytes(range(32))  # AES-256 anahtar boyutunda malzeme

    first_diff = _first_byte_flipped(key)
    last_diff = _last_byte_flipped(key)
    # Eşit değerli fakat ayrı nesne: gerçek tag karşılaştırmasında her zaman
    # iki farklı tampon (hesaplanan tag vs gelen tag) karşılaştırılır.
    identical = bytes(key)

    # Doğruluk kontrolleri: yalnızca ilgili bayt farklı olmalı
    assert hmac.compare_digest(key, identical)
    assert not hmac.compare_digest(key, first_diff)
    assert not hmac.compare_digest(key, last_diff)
    assert first_diff[0] != key[0] and first_diff[1:] == key[1:]
    assert last_diff[:-1] == key[:-1] and last_diff[-1] != key[-1]

    scenarios = _timed_samples(
        hmac.compare_digest,
        key,
        {
            "identical": identical,
            "first_byte_diff": first_diff,
            "last_byte_diff": last_diff,
        },
        batch=COMPARISON_BATCH_SIZE,
    )
    stats = {name: _timing_stats(samples) for name, samples in scenarios.items()}
    spread = _relative_spread([s["trimmed_mean"] for s in stats.values()])

    assert spread < ACCEPTABLE_VARIANCE, (
        f"Sabit zamanlı karşılaştırma eşiği aşıldı: göreli sapma {spread:.2%} "
        f"(esik {ACCEPTABLE_VARIANCE:.0%})\n{_report(stats)}"
    )


# ---------------------------------------------------------------------------
# constant_time_equal sarmalayıcısı: doğruluk + zamanlama
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("size", [GCM_TAG_SIZE, 32])
def test_constant_time_equal_helper_timing(size):
    """constant_time_equal, GCM tag (16B) ve anahtar (32B) boyutlarında sabit zamanlı olmalı."""
    secret = bytes((i * 13 + 7) & 0xFF for i in range(size))
    first_diff = _first_byte_flipped(secret)
    last_diff = _last_byte_flipped(secret)
    identical = bytes(secret)  # eşit değerli ayrı nesne

    assert constant_time_equal(secret, identical)
    assert not constant_time_equal(secret, first_diff)
    assert not constant_time_equal(secret, last_diff)
    assert not constant_time_equal(secret, secret[:-1])  # uzunluk farkı reddedilmeli

    scenarios = _timed_samples(
        constant_time_equal,
        secret,
        {
            "identical": identical,
            "first_byte_diff": first_diff,
            "last_byte_diff": last_diff,
        },
        batch=COMPARISON_BATCH_SIZE,
    )
    stats = {name: _timing_stats(samples) for name, samples in scenarios.items()}
    spread = _relative_spread([s["trimmed_mean"] for s in stats.values()])

    assert spread < ACCEPTABLE_VARIANCE, (
        f"constant_time_equal zamanlama eşiği aşıldı: göreli sapma {spread:.2%}\n"
        f"{_report(stats)}"
    )


# ---------------------------------------------------------------------------
# ML-KEM: shared secret karşılaştırması ve decapsulation zamanlaması
# ---------------------------------------------------------------------------


def test_ml_kem_shared_secret_comparison_is_constant_time():
    """ML-KEM shared secret karşılaştırmaları sabit zamanlı yapılmalı."""
    public_key, private_key = ml_kem_keygen()
    shared_secret, ciphertext = ml_kem_encapsulate(public_key)
    recovered = ml_kem_decapsulate(private_key, ciphertext)

    assert constant_time_equal(recovered, shared_secret)

    first_diff = _first_byte_flipped(recovered)
    last_diff = _last_byte_flipped(recovered)

    scenarios = _timed_samples(
        constant_time_equal,
        recovered,
        {
            "identical": shared_secret,
            "first_byte_diff": first_diff,
            "last_byte_diff": last_diff,
        },
        batch=COMPARISON_BATCH_SIZE,
    )
    stats = {name: _timing_stats(samples) for name, samples in scenarios.items()}
    spread = _relative_spread([s["trimmed_mean"] for s in stats.values()])

    assert spread < ACCEPTABLE_VARIANCE, (
        f"ML-KEM shared secret karşılaştırması zamanlama eşiği aşıldı: {spread:.2%}\n"
        f"{_report(stats)}"
    )


def test_ml_kem_decapsulation_timing_is_input_independent():
    """
    ML-KEM decapsulation süresi ciphertext geçerliliğinden bağımsız olmalı.

    FIPS 203 implicit rejection, geçersiz ciphertext için de aynı hesaplama
    yolunu izler; geçerli ve kurcalanmış ciphertext decapsulation süreleri
    birbirine yakın kalmalıdır.
    """
    public_key, private_key = ml_kem_keygen()
    shared_secret, ciphertext = ml_kem_encapsulate(public_key)
    tampered = _first_byte_flipped(ciphertext)

    assert constant_time_equal(ml_kem_decapsulate(private_key, ciphertext), shared_secret)
    assert not constant_time_equal(ml_kem_decapsulate(private_key, tampered), shared_secret)

    samples = _timed_samples(
        ml_kem_decapsulate,
        private_key,
        {"valid_ciphertext": ciphertext, "tampered_ciphertext": tampered},
        KEM_DECAPS_ITERATIONS,
        warmup=100,
    )
    stats = {
        name: _timing_stats(times, trim_fraction=0.10)
        for name, times in samples.items()
    }
    spread = _relative_spread([s["trimmed_mean"] for s in stats.values()])

    assert spread < KEM_DECAPS_ACCEPTABLE_VARIANCE, (
        f"ML-KEM decapsulation zamanlaması girdiye bağımlı görünüyor: {spread:.2%}\n"
        f"{_report(stats)}"
    )


# ---------------------------------------------------------------------------
# hybrid_decrypt: sabit zamanlı tag doğrulaması saplandırılmış paketleri reddetmeli
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def encrypted_sample():
    """Tüm tag doğrulama testlerinin paylaştığı tek hybrid şifreleme örneği."""
    public_key, private_key = generate_kyber_keys()
    encrypted = hybrid_encrypt(PLAINTEXT, public_key)
    return encrypted, private_key


def test_hybrid_roundtrip_with_constant_time_tag_verification(encrypted_sample):
    """Sabit zamanlı tag doğrulaması geçerli paketleri bozmamalı."""
    encrypted, private_key = encrypted_sample
    assert constant_time_equal(hybrid_decrypt(encrypted, private_key), PLAINTEXT)


def test_hybrid_decrypt_rejects_tag_differing_in_last_byte(encrypted_sample):
    """Son baytı farklı GCM tag'i sabit zamanlı doğrulamada reddedilmeli."""
    encrypted, private_key = encrypted_sample
    tampered = bytearray(encrypted["ciphertext"])
    tampered[-1] ^= 0x01

    with pytest.raises(ValueError):
        hybrid_decrypt({**encrypted, "ciphertext": bytes(tampered)}, private_key)


def test_hybrid_decrypt_rejects_tag_differing_in_first_byte(encrypted_sample):
    """İlk baytı farklı GCM tag'i sabit zamanlı doğrulamada reddedilmeli."""
    encrypted, private_key = encrypted_sample
    tampered = bytearray(encrypted["ciphertext"])
    tampered[-GCM_TAG_SIZE] ^= 0x01

    with pytest.raises(ValueError):
        hybrid_decrypt({**encrypted, "ciphertext": bytes(tampered)}, private_key)


def test_hybrid_decrypt_rejects_tampered_ciphertext_body(encrypted_sample):
    """Ciphertext gövdesindeki tek bit değişikliği reddedilmeli."""
    encrypted, private_key = encrypted_sample
    tampered = bytearray(encrypted["ciphertext"])
    tampered[0] ^= 0x01

    with pytest.raises(ValueError):
        hybrid_decrypt({**encrypted, "ciphertext": bytes(tampered)}, private_key)


def test_hybrid_decrypt_rejects_tampered_chaos_seed(encrypted_sample):
    """Kurcalanmış chaos seed yanlış anahtar üretmeli ve tag doğrulaması düşmeli."""
    encrypted, private_key = encrypted_sample
    tampered = bytearray(encrypted["chaos_seed"])
    tampered[0] ^= 0x01

    with pytest.raises(ValueError):
        hybrid_decrypt({**encrypted, "chaos_seed": bytes(tampered)}, private_key)


def test_hybrid_decrypt_rejects_tampered_kyber_ciphertext(encrypted_sample):
    """Kurcalanmış KEM ciphertext implicit rejection'a yol açmalı ve reddedilmeli."""
    encrypted, private_key = encrypted_sample
    tampered = bytearray(encrypted["kyber_ciphertext"])
    tampered[0] ^= 0x01

    with pytest.raises(ValueError):
        hybrid_decrypt({**encrypted, "kyber_ciphertext": bytes(tampered)}, private_key)


# ---------------------------------------------------------------------------
# Regresyon: kaynak kodda savunmasız karşılaştırma desenlerine geri dönülmemeli
# ---------------------------------------------------------------------------


def test_crypto_engine_uses_explicit_constant_time_verification():
    """crypto_engine.py tag doğrulamasını açıkça hmac.compare_digest ile yapmalı."""
    source = (PROJECT_ROOT / "src" / "crypto_engine.py").read_text(encoding="utf-8")

    assert "hmac.compare_digest" in source
    assert "constant_time_equal" in source
    assert "decrypt_and_verify" not in source  # örtük kütüphane doğrulamasına dönülmemeli


def test_hybrid_cipher_uses_constant_time_version_check():
    """hybrid_cipher.py sürüm baytını sabit zamanlı karşılaştırmalı."""
    source = (PROJECT_ROOT / "src" / "hybrid_cipher.py").read_text(encoding="utf-8")

    assert "compare_digest" in source
    assert "!= self.VERSION" not in source
