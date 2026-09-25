import hashlib
import hmac
import os
import secrets
import struct

import numpy as np
from Crypto.Cipher import AES
from pqcrypto.kem.ml_kem_768 import decaps as _ml_kem_decaps
from pqcrypto.kem.ml_kem_768 import encaps as _ml_kem_encaps
from pqcrypto.kem.ml_kem_768 import keygen as _ml_kem_keygen

GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
CHUNK_SIZE = 65536
STREAM_NONCE_SIZE = 16
STREAM_CHUNK_COUNT_SIZE = 4
STREAM_HEADER_SIZE = STREAM_NONCE_SIZE + STREAM_CHUNK_COUNT_SIZE
STREAM_AAD_INFO = b"chaoscrypt-v1-stream"
ML_KEM_PRIVATE_KEY_SIZE = 2400
ML_KEM_CIPHERTEXT_SIZE = 1088
LORENZ_IC_BOUND = 15.0
LORENZ_STATE_BOUND = 50.0


def _bytes_to_unit_interval(chunk: bytes) -> float:
    """8 byte'ı [0, 1) aralığına çevirir."""
    return int.from_bytes(chunk, "little") / 2**64


def _seed_to_lorenz_state(seed: bytes) -> tuple[float, float, float]:
    """Seed'in ilk 24 byte'ını [-15, 15] aralığındaki Lorenz başlangıç değerlerine eşler."""
    material = seed[:24]
    if len(seed) >= 32:
        values = np.array(
            [
                _bytes_to_unit_interval(material[i * 8 : (i + 1) * 8])
                * (2.0 * LORENZ_IC_BOUND)
                - LORENZ_IC_BOUND
                for i in range(3)
            ],
            dtype=np.float64,
        )
        return tuple(values)

    values = np.frombuffer(material, dtype=np.float64).astype(np.float64, copy=True)
    values = np.nan_to_num(values, nan=0.0, posinf=LORENZ_IC_BOUND, neginf=-LORENZ_IC_BOUND)

    if np.any(np.abs(values) > LORENZ_IC_BOUND):
        # Ham float64 taşmasını önlemek için her 8 byte'ı düzgün dağılımlı [-15, 15]'e çevir.
        for i in range(3):
            unit = _bytes_to_unit_interval(material[i * 8 : (i + 1) * 8])
            values[i] = unit * (2.0 * LORENZ_IC_BOUND) - LORENZ_IC_BOUND

    return tuple(np.clip(values, -LORENZ_IC_BOUND, LORENZ_IC_BOUND))


def _stabilize_lorenz_state(x: float, y: float, z: float) -> tuple[float, float, float]:
    """Sonsuz/NaN veya aşırı büyük durumları Lorenz attractor ölçeğine geri çeker."""
    state = np.array([x, y, z], dtype=np.float64)
    if not np.all(np.isfinite(state)):
        state = np.nan_to_num(state, nan=0.0, posinf=LORENZ_STATE_BOUND, neginf=-LORENZ_STATE_BOUND)

    max_abs = np.max(np.abs(state))
    if max_abs > LORENZ_STATE_BOUND:
        state *= LORENZ_STATE_BOUND / max_abs

    return float(state[0]), float(state[1]), float(state[2])


def generate_chaos_key(seed: bytes | None = None, iterations: int = 10000) -> bytes:
    """
    Lorenz attractor kullanarak 256-bit şifreleme anahtarı üretir.

    Seed verilmezse OS CSPRNG (`secrets.token_bytes(32)`) kullanılır. Lorenz
    çıktısı bu seed ile SHA-256 üzerinden birleştirilir.

    Args:
        seed: 24 veya 32 byte'lık başlangıç değeri. None ise OS CSPRNG üretir.
        iterations: Lorenz iterasyon sayısı (default: 10000)

    Returns:
        32 byte'lık SHA-256 anahtar (kaos + CSPRNG karışımı)
    """
    if seed is None:
        seed = secrets.token_bytes(32)
    if len(seed) not in (24, 32):
        raise ValueError("seed must be 24 or 32 bytes")

    x, y, z = _seed_to_lorenz_state(seed)

    sigma = 10.0
    rho = 28.0
    beta = 8.0 / 3.0
    dt = 0.01

    with np.errstate(over="ignore", invalid="ignore", divide="ignore"):
        for _ in range(iterations):
            dx = sigma * (y - x)
            dy = x * (rho - z) - y
            dz = x * y - beta * z
            next_x = x + dt * dx
            next_y = y + dt * dy
            next_z = z + dt * dz

            if not (np.isfinite(next_x) and np.isfinite(next_y) and np.isfinite(next_z)):
                break

            x, y, z = _stabilize_lorenz_state(next_x, next_y, next_z)

    final_state = np.array([x, y, z], dtype=np.float64)
    state_bytes = final_state.tobytes()
    return hashlib.sha256(state_bytes + seed).digest()


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """
    İki bayt dizisini sabit zamanlı karşılaştırır (`hmac.compare_digest`).

    MAC tag'leri, anahtarlar ve shared secret gibi gizli bayt dizilerinde
    `==` / `!=` operatörleri ilk farklı baytta erken çıkış yapar ve zamanlama
    yan kanalı sızdırır; bu sarmalayıcı içerikten bağımsız sabit sürede çalışır.
    """
    return hmac.compare_digest(a, b)


def ml_kem_keygen() -> tuple[bytes, bytes]:
    """ML-KEM-768 (FIPS 203) public/private anahtar çifti üretir."""
    public_key, private_key = _ml_kem_keygen()
    return bytes(public_key), bytes(private_key)


def ml_kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Public key ile shared secret ve ciphertext üretir (ML-KEM encapsulation).

    Dönüş sırası mevcut API ile uyumludur: (shared_secret, ciphertext).
    """
    ciphertext, shared_secret = _ml_kem_encaps(public_key)
    return bytes(shared_secret), bytes(ciphertext)


def ml_kem_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """
    Ciphertext'ten shared secret'i çıkarır (ML-KEM decapsulation).

    PQClean tabanlı ML-KEM-768, FO (Fujisaki-Okamoto) dönüşümünün ciphertext
    yeniden-şifreleme karşılaştırmasını sabit zamanlı yürütür ve geçersiz
    ciphertext'lerde gizli reddetme (implicit rejection) uygular; bu Python
    sarmalayıcıda secret-dependent dal yoktur. Boyut denetimi yalnızca kamu
    uzunluk bilgisi üzerinden yapılır.
    """
    if len(private_key) != ML_KEM_PRIVATE_KEY_SIZE:
        raise ValueError(f"private key must be {ML_KEM_PRIVATE_KEY_SIZE} bytes")
    if len(ciphertext) != ML_KEM_CIPHERTEXT_SIZE:
        raise ValueError(f"ciphertext must be {ML_KEM_CIPHERTEXT_SIZE} bytes")
    return bytes(_ml_kem_decaps(private_key, ciphertext))


def generate_kyber_keys() -> tuple[bytes, bytes]:
    """Kyber Round 3 yerine FIPS 203 ML-KEM-768 anahtar çifti üretir."""
    return ml_kem_keygen()


def kyber_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """Mevcut Kyber API'sini ML-KEM-768 encapsulation ile karşılar."""
    return ml_kem_encapsulate(public_key)


def kyber_decapsulate(private_key: bytes, ciphertext: bytes) -> bytes:
    """Mevcut Kyber API'sini ML-KEM-768 decapsulation ile karşılar."""
    return ml_kem_decapsulate(private_key, ciphertext)


def _derive_final_key(shared_secret: bytes, chaos_key: bytes) -> bytes:
    """Kyber shared secret ile chaos anahtarını birleştirerek AES anahtarı türet."""
    return hashlib.sha3_256(shared_secret + chaos_key).digest()


def hybrid_encrypt(
    plaintext: bytes,
    recipient_public_key: bytes,
    associated_data: bytes | None = None,
) -> dict:
    """
    Lorenz + Kyber + AES-256-GCM hibrit şifreleme.

    Rastgele chaos seed, Kyber KEM shared secret ve AES-GCM ile plaintext şifrelenir.
    `associated_data` verilirse AEAD kullanılır: veri şifrelenmez, yalnızca
    GCM authentication tag hesabına katılarak bütünlüğü güvence altına alınır.

    Args:
        plaintext: Şifrelenecek veri.
        recipient_public_key: Alıcının ML-KEM public anahtarı.
        associated_data: AEAD için ek kimlik doğrulama verisi (AAD). None ise
            AAD kullanılmaz ve mevcut davranış birebir korunur. Verilirse
            şifrelenmez, yalnızca GCM tag hesabına katılır; `hybrid_decrypt`
            çağrısında aynı bytes ile iletilmelidir.

    Returns:
        "ciphertext" (ciphertext + tag), "nonce", "kyber_ciphertext" ve
        "chaos_seed" anahtarlarını içeren sözlük.

    Raises:
        ValueError: `associated_data` None değil ve bytes tipinde değilse.
    """
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("associated_data must be bytes or None")

    chaos_seed = secrets.token_bytes(32)
    chaos_key = generate_chaos_key(chaos_seed)
    shared_secret, kyber_ciphertext = kyber_encapsulate(recipient_public_key)
    final_key = _derive_final_key(shared_secret, chaos_key)

    nonce = os.urandom(GCM_NONCE_SIZE)
    cipher = AES.new(final_key, AES.MODE_GCM, nonce=nonce)
    if associated_data is not None:
        cipher.update(associated_data)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return {
        "ciphertext": ciphertext + tag,
        "nonce": nonce,
        "kyber_ciphertext": kyber_ciphertext,
        "chaos_seed": chaos_seed,
    }


def hybrid_decrypt(
    data: dict,
    recipient_private_key: bytes,
    associated_data: bytes | None = None,
) -> bytes:
    """
    Hibrit şifreli veriyi çözer.

    Kyber decapsulation ve Lorenz anahtarı ile final AES anahtarı türetilir,
    ardından AES-256-GCM ile plaintext elde edilir. GCM tag doğrulaması
    `constant_time_equal` ile sabit zamanlı yapılır; tag eşleşmezse hata
    verilir ve plaintext hiçbir koşulda döndürülmez.

    Args:
        data: `hybrid_encrypt` çıktısı (ciphertext, nonce, kyber_ciphertext,
            chaos_seed).
        recipient_private_key: Alıcının ML-KEM private anahtarı.
        associated_data: Şifreleme sırasında kullanılan AEAD ek kimlik
            doğrulama verisi (AAD). None ise AAD'siz paketler çözülür (geriye
            dönük uyumluluk). Şifrelemede AAD kullanıldıysa çözmede de aynı
            bytes verilmelidir; eksik veya farklı AAD tag doğrulamasını
            başarısız kılar.

    Returns:
        Tag doğrulaması yapılmış plaintext.

    Raises:
        ValueError: `associated_data` None değil ve bytes tipinde değilse
            ya da GCM tag doğrulaması başarısız olursa.
    """
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("associated_data must be bytes or None")

    shared_secret = kyber_decapsulate(recipient_private_key, data["kyber_ciphertext"])
    chaos_key = generate_chaos_key(data["chaos_seed"])
    final_key = _derive_final_key(shared_secret, chaos_key)

    encrypted = data["ciphertext"]
    ciphertext = encrypted[:-GCM_TAG_SIZE]
    tag = encrypted[-GCM_TAG_SIZE:]

    cipher = AES.new(final_key, AES.MODE_GCM, nonce=data["nonce"])
    if associated_data is not None:
        cipher.update(associated_data)
    plaintext = cipher.decrypt(ciphertext)

    # PyCryptodome decrypt tarafında `digest()` çağrılamaz; tag'i bizim
    # tarafımızda açıkça sabit zamanlı doğrulamak için plaintext'i aynı nonce
    # ile yeniden şifreliyoruz (GCM-CTR deterministiktir, tag yeniden oluşur)
    # ve karşılaştırmayı `constant_time_equal` ile yapıyoruz. Başarılı ve
    # başarısız yollar eşit iş yapar; plaintext yalnızca eşleşmede döner.
    # AAD kullanıldıysa doğrulayıcıya da aynı AAD beslenir; tag böylece
    # encrypt tarafındaki hesapla birebir aynı şekilde yeniden oluşur.
    verifier = AES.new(final_key, AES.MODE_GCM, nonce=data["nonce"])
    if associated_data is not None:
        verifier.update(associated_data)
    verifier.encrypt(plaintext)
    computed_tag = verifier.digest()
    if not constant_time_equal(computed_tag, tag):
        raise ValueError("AES-GCM authentication failed: tag mismatch")
    return plaintext


def _validate_stream_arguments(
    input_path: str,
    output_path: str,
    key: bytes,
    associated_data: bytes | None,
) -> None:
    """
    `encrypt_stream` / `decrypt_stream` için ortak girdi doğrulaması.

    Geçersiz girdiler tek istisna tipi (`ValueError`) ile reddedilir; tip
    denetimleri boyut denetimlerinden önce yapılır çünkü `len()` None gibi
    geçersiz tiplerde `TypeError` fırlatır ve ValueError sözleşmesini bozar.
    """
    if not isinstance(input_path, str):
        raise ValueError("input_path must be str")
    if not isinstance(output_path, str):
        raise ValueError("output_path must be str")
    if not isinstance(key, bytes):
        raise ValueError("key must be bytes")
    if len(key) != 32:
        raise ValueError("key must be 32 bytes for AES-256")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("associated_data must be bytes or None")


def _stream_chunk_nonce(file_nonce: bytes, chunk_index: int) -> bytes:
    """
    Dosya nonce'undan chunk'a özgü 12 byte'lık GCM nonce'u türetir.

    Aynı anahtar altında aynı GCM nonce'unun iki kez kullanılması GCM
    authentication anahtarını tamamen ifşa eder; bu yüzden her chunk, dosya
    nonce'u ile chunk indeksinden SHA-256 üzerinden türetilmiş benzersiz bir
    nonce kullanır. Türetim deterministiktir: `decrypt_stream` aynı dosya
    nonce'u ve indeksten aynı değeri hesaplar.
    """
    material = file_nonce + struct.pack("<I", chunk_index)
    return hashlib.sha256(material).digest()[:GCM_NONCE_SIZE]


def _stream_chunk_aad(
    associated_data: bytes,
    chunk_index: int,
    chunk_count: int,
) -> bytes:
    """
    Chunk başına GCM AAD'ini oluşturur.

    AAD; protokol ayrımı (`STREAM_AAD_INFO`), kullanıcının `associated_data`
    verisi, chunk indeksi ve toplam chunk sayısından oluşur. İndeks chunk'ların
    yeniden sıralanmasını, toplam sayı ise akışın budanmasını veya uzatılmasını
    tag doğrulamasına bağlar.
    """
    return (
        STREAM_AAD_INFO
        + associated_data
        + struct.pack("<II", chunk_index, chunk_count)
    )


def encrypt_stream(
    input_path: str,
    output_path: str,
    key: bytes,
    associated_data: bytes | None = None,
) -> None:
    """
    Büyük dosyaları 64KB'lık chunk'lar halinde belleğe almadan şifreler.

    Girdi dosyası `CHUNK_SIZE` byte'lık parçalarla okunur ve her parça
    AES-256-GCM ile ayrı ayrı şifrelenir; 16 byte'lık GCM tag'i ciphertext'in
    sonuna eklenerek çıktıya yazılır. Çıktı formatı (little-endian):
    `[16 byte nonce][4 byte chunk_count][chunk'lar...]`. Son chunk dışındaki
    tüm chunk'lar tam `CHUNK_SIZE` byte plaintext içerir; son chunk kalan
    byte'ları içerir ve boş chunk yazılmaz (boş dosya → chunk_count = 0).

    Güvenlik notları: Dosya başına tek rastgele nonce üretilip başlığa
    yazılır; her chunk bu nonce'tan türetilmiş benzersiz bir GCM nonce'u ile
    şifrelenir (aynı nonce'un aynı anahtar altında tekrarı GCM'de yıkıcıdır).
    Chunk indeksi ve toplam chunk sayısı her chunk'ın AAD'ine bağlanır;
    böylece chunk'lar yeniden sıralanamaz ve akış budanıp uzatılamaz.
    `associated_data` verilirse şifrelenmeden her chunk'ın tag hesabına
    katılır ve `decrypt_stream` çağrısında aynı bytes ile iletilmelidir.

    Args:
        input_path: Şifrelenecek girdi dosyasının yolu.
        output_path: Şifreli çıktının yazılacağı dosya yolu.
        key: 32 byte'lık AES-256 anahtarı.
        associated_data: AEAD için ek kimlik doğrulama verisi (AAD). None ise
            AAD kullanılmaz. Şifrelenmez, yalnızca tag hesabına katılır.

    Returns:
        None; sonuç `output_path` dosyasına yazılır.

    Raises:
        ValueError: `input_path` veya `output_path` str değilse, `key` bytes
            tipinde ve tam 32 byte değilse, `associated_data` None dışında
            bytes değilse ya da girdi dosyası şifreleme sırasında boyut
            değiştirirse.
        FileNotFoundError: Girdi dosyası yoksa veya çıktının üst dizini yoksa.
    """
    _validate_stream_arguments(input_path, output_path, key, associated_data)

    file_nonce = os.urandom(STREAM_NONCE_SIZE)
    aad = associated_data if associated_data is not None else b""

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        # Boyut, açılan tanıtıcıdan alınır; ayrı bir getsize çağrısında dosya
        # değişse bile (TOCTOU) tutarlı bir chunk sayısı hesaplanır.
        file_size = os.fstat(fin.fileno()).st_size
        chunk_count = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

        fout.write(file_nonce + struct.pack("<I", chunk_count))

        index = 0
        while True:
            chunk = fin.read(CHUNK_SIZE)
            if not chunk:
                break
            if index >= chunk_count:
                # Başlıktaki chunk sayısı sabit; eksik chunk'lı bozuk bir
                # akış yazmak yerine şifrelemeyi reddet.
                raise ValueError("input file grew during encryption")

            chunk_nonce = _stream_chunk_nonce(file_nonce, index)
            cipher = AES.new(key, AES.MODE_GCM, nonce=chunk_nonce)
            cipher.update(_stream_chunk_aad(aad, index, chunk_count))
            ciphertext, tag = cipher.encrypt_and_digest(chunk)
            fout.write(ciphertext + tag)
            index += 1

        if index != chunk_count:
            raise ValueError("input file shrank during encryption")


def decrypt_stream(
    input_path: str,
    output_path: str,
    key: bytes,
    associated_data: bytes | None = None,
) -> None:
    """
    `encrypt_stream` ile şifrelenmiş bir dosyayı belleğe almadan çözer.

    Başlık (`[16 byte nonce][4 byte chunk_count]`) okunduktan sonra her chunk
    sırayla okunur, dosya nonce'undan türetilmiş GCM nonce'u ile çözülür ve
    tag'i `constant_time_equal` ile sabit zamanlı doğrulanır. Plaintext
    yalnızca tag doğrulamasını geçen chunk'lar için diske yazılır; herhangi
    bir chunk başarısız olursa akış `ValueError` ile durdurulur. Girdi,
    akışın sonunda fazladan veri taşıyamaz.

    Args:
        input_path: Şifreli girdi dosyasının yolu.
        output_path: Çözülmüş çıktının yazılacağı dosya yolu.
        key: Şifrelemede kullanılan 32 byte'lık AES-256 anahtarı.
        associated_data: Şifreleme sırasında kullanılan AEAD ek kimlik
            doğrulama verisi (AAD). Şifrelemede AAD kullanıldıysa çözmede de
            aynı bytes ile verilmelidir; eksik veya farklı AAD tag
            doğrulamasını başarısız kılar.

    Returns:
        None; sonuç `output_path` dosyasına yazılır.

    Raises:
        ValueError: Girdi argümanları geçersizse (yol tipleri, anahtar tipi
            veya boyutu, AAD tipi), dosya akış formatına uymuyorsa (eksik
            başlık, kısa chunk, fazladan veri) ya da herhangi bir chunk'ın
            GCM tag doğrulaması başarısızsa.
        FileNotFoundError: Girdi dosyası yoksa veya çıktının üst dizini yoksa.
    """
    _validate_stream_arguments(input_path, output_path, key, associated_data)

    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        header = fin.read(STREAM_HEADER_SIZE)
        if len(header) != STREAM_HEADER_SIZE:
            raise ValueError("invalid stream file: missing header")

        file_nonce = header[:STREAM_NONCE_SIZE]
        (chunk_count,) = struct.unpack(
            "<I", header[STREAM_NONCE_SIZE:STREAM_HEADER_SIZE]
        )
        aad = associated_data if associated_data is not None else b""

        for index in range(chunk_count):
            chunk = fin.read(CHUNK_SIZE + GCM_TAG_SIZE)
            if index < chunk_count - 1:
                if len(chunk) != CHUNK_SIZE + GCM_TAG_SIZE:
                    raise ValueError(
                        f"invalid stream file: chunk {index} is truncated"
                    )
            elif len(chunk) < GCM_TAG_SIZE:
                raise ValueError("invalid stream file: final chunk is truncated")

            ciphertext = chunk[:-GCM_TAG_SIZE]
            tag = chunk[-GCM_TAG_SIZE:]
            chunk_aad = _stream_chunk_aad(aad, index, chunk_count)

            chunk_nonce = _stream_chunk_nonce(file_nonce, index)
            cipher = AES.new(key, AES.MODE_GCM, nonce=chunk_nonce)
            cipher.update(chunk_aad)
            plaintext = cipher.decrypt(ciphertext)

            # PyCryptodome decrypt tarafında `digest()` çağrılamaz; tag'i bizim
            # tarafımızda açıkça sabit zamanlı doğrulamak için plaintext'i aynı
            # nonce ve AAD ile yeniden şifreliyoruz (GCM-CTR deterministiktir,
            # tag yeniden oluşur) ve karşılaştırmayı `constant_time_equal` ile
            # yapıyoruz. Başarılı ve başarısız yollar eşit iş yapar; plaintext
            # yalnızca eşleşmede diske yazılır.
            verifier = AES.new(key, AES.MODE_GCM, nonce=chunk_nonce)
            verifier.update(chunk_aad)
            verifier.encrypt(plaintext)
            computed_tag = verifier.digest()
            if not constant_time_equal(computed_tag, tag):
                raise ValueError(f"chunk {index}: AES-GCM authentication failed")
            fout.write(plaintext)

        if fin.read(1) != b"":
            raise ValueError("invalid stream file: trailing data after stream")
