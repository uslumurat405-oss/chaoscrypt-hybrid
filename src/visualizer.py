import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from src.chaos_engine import ChaosEngine
from src.hybrid_cipher import HybridCipher
import os

os.makedirs("visuals", exist_ok=True)

def plot_lorenz_3d(seed: str = "test_seed", n: int = 10000):
    """3D Lorenz attractor visualization."""
    engine = ChaosEngine(seed)
    data = engine.generate(n)
    
    fig = plt.figure(figsize=(10, 8), facecolor='#1a1a2e')
    ax = fig.add_subplot(111, projection='3d', facecolor='#1a1a2e')
    
    # Color by Z value
    z_norm = (data[:, 2] - data[:, 2].min()) / (data[:, 2].max() - data[:, 2].min())
    
    for i in range(len(data) - 1):
        ax.plot(data[i:i+2, 0], data[i:i+2, 1], data[i:i+2, 2],
                color=plt.cm.viridis(z_norm[i]), alpha=0.5, linewidth=0.5)
    
    ax.set_title("Lorenz Attractor - ChaosCrypt Engine", 
                 color='white', fontsize=14, pad=20)
    ax.set_xlabel("X", color='white')
    ax.set_ylabel("Y", color='white')
    ax.set_zlabel("Z", color='white')
    ax.tick_params(colors='white')
    
    plt.tight_layout()
    plt.savefig("visuals/lorenz_3d.png", dpi=300, bbox_inches='tight')
    plt.close()
    print("✅ Saved: visuals/lorenz_3d.png")

def plot_histogram_comparison():
    """Compare plaintext vs encrypted data histograms."""
    plaintext = b"Hello World! " * 1000
    cipher = HybridCipher()
    encrypted = cipher.encrypt(plaintext, "password123")
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5), facecolor='#1a1a2e')
    
    # Plaintext histogram
    ax1.hist(list(plaintext), bins=256, color='blue', alpha=0.7)
    ax1.set_title("Plaintext Distribution", color='white')
    ax1.set_facecolor('#1a1a2e')
    ax1.tick_params(colors='white')
    
    # Encrypted histogram
    ax2.hist(list(encrypted[:len(plaintext)]), bins=256, color='red', alpha=0.7)
    ax2.set_title("Encrypted Distribution (Uniform)", color='white')
    ax2.set_facecolor('#1a1a2e')
    ax2.tick_params(colors='white')
    
    plt.tight_layout()
    plt.savefig("visuals/histogram_comparison.png", dpi=300, bbox_inches='tight',
                facecolor='#1a1a2e')
    plt.close()
    print("✅ Saved: visuals/histogram_comparison.png")

def plot_entropy_analysis():
    """Show entropy of chaotic bytes."""
    engine = ChaosEngine("test_seed")
    data = engine.extract_bytes(10000)
    
    # Calculate rolling entropy
    chunk_size = 1000
    entropies = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        freq = np.bincount(np.frombuffer(chunk, dtype=np.uint8), minlength=256) / len(chunk)
        freq = freq[freq > 0]
        entropy = -np.sum(freq * np.log2(freq))
        entropies.append(entropy)
    
    fig, ax = plt.subplots(figsize=(10, 5), facecolor='#1a1a2e')
    ax.plot(range(len(entropies)), entropies, 'b-', linewidth=2)
    ax.axhline(y=8.0, color='r', linestyle='--', label='Max Entropy (8.0)')
    ax.set_title("Shannon Entropy Over Time", color='white', fontsize=14)
    ax.set_xlabel("Chunk Index", color='white')
    ax.set_ylabel("Entropy (bits)", color='white')
    ax.set_facecolor('#1a1a2e')
    ax.tick_params(colors='white')
    ax.legend(facecolor='#1a1a2e', labelcolor='white')
    
    plt.tight_layout()
    plt.savefig("visuals/entropy_analysis.png", dpi=300, bbox_inches='tight',
                facecolor='#1a1a2e')
    plt.close()
    print("✅ Saved: visuals/entropy_analysis.png")

if __name__ == "__main__":
    plot_lorenz_3d()
    plot_histogram_comparison()
    plot_entropy_analysis()
    print("\n🎨 All visualizations saved to visuals/ folder")
