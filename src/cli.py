import click
import sys
from src.hybrid_cipher import HybridCipher
from src.analyzer import SecurityAnalyzer
from src.visualizer import plot_lorenz_3d, plot_histogram_comparison, plot_entropy_analysis

@click.group()
def cli():
    """ChaosCrypt - Chaos-based Hybrid Encryption Tool"""
    pass

@cli.command()
@click.option('-i', '--input', required=True, help='Input file path')
@click.option('-o', '--output', required=True, help='Output file path')
@click.option('-p', '--password', required=True, help='Encryption password')
def encrypt(input, output, password):
    """Encrypt a file."""
    cipher = HybridCipher()
    cipher.encrypt_file(input, password, output)
    click.echo(f"✅ Encrypted: {input} → {output}")

@cli.command()
@click.option('-i', '--input', required=True, help='Encrypted file path')
@click.option('-o', '--output', required=True, help='Output file path')
@click.option('-p', '--password', required=True, help='Decryption password')
def decrypt(input, output, password):
    """Decrypt a file."""
    cipher = HybridCipher()
    try:
        cipher.decrypt_file(input, password, output)
        click.echo(f"✅ Decrypted: {input} → {output}")
    except ValueError as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)

@cli.command()
def analyze():
    """Run security analysis."""
    SecurityAnalyzer.full_report()

@cli.command()
def visualize():
    """Generate visualizations."""
    click.echo("🎨 Generating visualizations...")
    plot_lorenz_3d()
    plot_histogram_comparison()
    plot_entropy_analysis()
    click.echo("✅ All visualizations saved to visuals/ folder")

if __name__ == "__main__":
    cli()
