import numpy as np
import hashlib
from mpmath import mp, mpf

class ChaosEngine:
    """Lorenz Attractor based chaotic bit generator.
    Uses Pi and Golden Ratio to prevent finite-precision collapse."""
    
    def __init__(self, master_seed: str):
        """Generate initial conditions from master seed."""
        # SHA-256 hash
        hash_bytes = hashlib.sha256(master_seed.encode()).digest()
        
        # Get Pi and Phi with 1000 digits precision
        mp.dps = 1000  # decimal places
        self.pi = mp.pi
        self.phi = (1 + mp.sqrt(5)) / 2
        
        # Generate initial conditions from hash (-10 to 10)
        self.x = (hash_bytes[0] / 255.0) * 20 - 10
        self.y = (hash_bytes[1] / 255.0) * 20 - 10
        self.z = (hash_bytes[2] / 255.0) * 20 - 10
        
        # Lorenz parameters
        self.sigma = 10
        self.rho = 28
        self.beta = 8/3
        
        self.iteration_count = 0
    
    def _rk4_step(self, x: float, y: float, z: float, dt: float = 0.01):
        """Solve Lorenz equations using 4th order Runge-Kutta."""
        def f(x, y, z):
            dx = self.sigma * (y - x)
            dy = x * (self.rho - z) - y
            dz = x * y - self.beta * z
            return dx, dy, dz
        
        k1x, k1y, k1z = f(x, y, z)
        k2x, k2y, k2z = f(x + dt*k1x/2, y + dt*k1y/2, z + dt*k1z/2)
        k3x, k3y, k3z = f(x + dt*k2x/2, y + dt*k2y/2, z + dt*k2z/2)
        k4x, k4y, k4z = f(x + dt*k3x, y + dt*k3y, z + dt*k3z)
        
        new_x = x + (dt/6) * (k1x + 2*k2x + 2*k3x + k4x)
        new_y = y + (dt/6) * (k1y + 2*k2y + 2*k3y + k4y)
        new_z = z + (dt/6) * (k1z + 2*k2z + 2*k3z + k4z)
        
        return new_x, new_y, new_z
    
    def _apply_perturbation(self, x: float, y: float, z: float):
        """Apply perturbation with Pi/Phi every 1000 iterations."""
        if self.iteration_count % 1000 != 0:
            return x, y, z
        
        # Get Pi and Phi digits
        digit_index = self.iteration_count // 1000
        pi_str = mp.nstr(self.pi, digit_index + 2)
        phi_str = mp.nstr(self.phi, digit_index + 502)
        
        pi_digit = int(pi_str[-1]) if len(pi_str) > digit_index else 0
        phi_digit = int(phi_str[-1]) if len(phi_str) > digit_index + 500 else 0
        
        # Apply small perturbation
        x += (pi_digit - 5) * 1e-15
        y += (phi_digit - 5) * 1e-15
        
        return x, y, z
    
    def generate(self, n: int) -> np.ndarray:
        """Run n iterations, return (n, 3) array."""
        # Transient: skip first 1000 iterations
        x, y, z = self.x, self.y, self.z
        for _ in range(1000):
            x, y, z = self._rk4_step(x, y, z)
            self.iteration_count += 1
        
        # Generate real data
        results = np.zeros((n, 3))
        for i in range(n):
            x, y, z = self._rk4_step(x, y, z)
            x, y, z = self._apply_perturbation(x, y, z)
            self.iteration_count += 1
            results[i] = [x, y, z]
        
        return results
    
    def extract_bytes(self, n: int) -> bytes:
        """Generate n bytes of chaotic data."""
        data = self.generate(n)
        
        # Normalize each column to 0-255
        x_bytes = ((data[:, 0] - data[:, 0].min()) / 
                   (data[:, 0].max() - data[:, 0].min()) * 255).astype(np.uint8)
        y_bytes = ((data[:, 1] - data[:, 1].min()) / 
                   (data[:, 1].max() - data[:, 1].min()) * 255).astype(np.uint8)
        z_bytes = ((data[:, 2] - data[:, 2].min()) / 
                   (data[:, 2].max() - data[:, 2].min()) * 255).astype(np.uint8)
        
        # XOR combine
        result = x_bytes ^ y_bytes ^ z_bytes
        return result.tobytes()
    
    def lyapunov_exponent(self, n: int = 50000, dt: float = 0.01) -> float:
        """Calculate Lyapunov exponent (positive = chaotic)."""
        # Two close initial conditions
        x1, y1, z1 = self.x, self.y, self.z
        x2, y2, z2 = self.x + 1e-10, self.y, self.z
        
        d0 = 1e-10
        total_log = 0.0
        
        for _ in range(n):
            x1, y1, z1 = self._rk4_step(x1, y1, z1, dt)
            x2, y2, z2 = self._rk4_step(x2, y2, z2, dt)
            
            dx, dy, dz = x2 - x1, y2 - y1, z2 - z1
            d = np.sqrt(dx**2 + dy**2 + dz**2)
            if d > 0:
                total_log += np.log(d / d0)
                scale = d0 / d
                x2 = x1 + dx * scale
                y2 = y1 + dy * scale
                z2 = z1 + dz * scale
        
        return total_log / (n * dt)
