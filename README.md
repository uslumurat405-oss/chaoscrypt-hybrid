# ChaosCrypt-Hybrid

Post-kuantum çağ için hibrit şifreleme motoru.

## 🧪 Özellikler

- **Lorenz Attractor** tabanlı kaotik anahtar üretimi
- **Kyber (Lattice)** post-kuantum anahtar değişimi (RSA-2048 geçici)
- **AES-256-GCM** endüstri standardı şifreleme
- **21/21 test geçti** ✅

## 🚀 Kurulum

```bash
pip install -r requirements.txt
'''

🧪 Testler

```bash
python -m pytest tests/ -v
```

## Mimari

Plaintext → [Lorenz Key] + [Kyber Shared Secret] → AES-256-GCM → Ciphertext

🛣️ Yol Haritası
Faz 1: Lorenz anahtar üretici
Faz 2: Kyber anahtar değişimi
Faz 3: Hibrit motor (AES-GCM)
Faz 4: Güvenlik testleri (Red Team)
Faz 5: FPGA prototipi
Faz 6: Boron-Grafen çip tasarımı
📄 Lisans
MIT License
👨‍ Geliştirici
Murat Uslu
GitHub: @uslumurat405-oss
