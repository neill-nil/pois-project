"""
PA #1 — One-Way Functions & Pseudorandom Generators
CS8.401: Principles of Information Security

Implements:
1. OWF — DLP-based: f(x) = g^x mod p
2. PRG from OWF — iterative hard-core-bit construction (HILL/Goldreich-Levin)
3. OWF from PRG (backward direction, PA#1b)
4. Statistical tests: frequency, runs, serial
5. Interface: seed(s), next_bits(n)
"""

import os
import sys
import math
import struct

# Import Miller-Rabin for safe prime generation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa13_miller_rabin'))
from miller_rabin import mod_exp, gen_safe_prime, is_prime


# ─────────────────────────────────────────────
# DLP Group Parameters
# ─────────────────────────────────────────────
class DLPGroup:
    """
    Cyclic group Zp* of prime order q where p = 2q + 1 (safe prime).
    g is a generator of the prime-order-q subgroup.
    """
    def __init__(self, bits=64):
        self.p, self.q = gen_safe_prime(bits)
        # Find generator g of order q (quadratic residues)
        self.g = self._find_generator()

    def _find_generator(self):
        """Find a generator of the order-q subgroup of Zp*."""
        p, q = self.p, self.q
        while True:
            h = int.from_bytes(os.urandom(8), 'big') % (p - 2) + 2
            g = mod_exp(h, 2, p)  # Square to get element of order q
            if g != 1:
                # Verify order is q
                if mod_exp(g, q, p) == 1:
                    return g

    def exp(self, x: int) -> int:
        """Compute g^x mod p."""
        return mod_exp(self.g, x % self.q, self.p)


# ─────────────────────────────────────────────
# One-Way Function (DLP-based)
# ─────────────────────────────────────────────
class OWF_DLP:
    """
    f(x) = g^x mod p
    Easy to compute, hard to invert (DLP assumption).
    """
    def __init__(self, bits=64):
        self.group = DLPGroup(bits)
        self.p = self.group.p
        self.q = self.group.q
        self.g = self.group.g

    def evaluate(self, x: int) -> int:
        """Evaluate f(x) = g^x mod p."""
        return mod_exp(self.g, x % self.q, self.p)

    def verify_hardness(self, num_trials=20):
        """
        Demonstrate that random inversion fails.
        Try to invert f(x) by brute force for small groups only.
        """
        print(f"  OWF hardness demo: group order q = {self.q}")
        print(f"  Brute-force inversion requires O(q) ≈ {self.q} operations")
        print(f"  Random guessing probability per attempt: 1/{self.q}")
        # For tiny groups, demonstrate brute force
        if self.q < 10000:
            x_secret = int.from_bytes(os.urandom(4), 'big') % self.q
            y = self.evaluate(x_secret)
            found = None
            for guess in range(self.q):
                if mod_exp(self.g, guess, self.p) == y:
                    found = guess
                    break
            print(f"  Small group brute force succeeded: found x={found} (correct={x_secret % self.q})")
        else:
            print(f"  Large group: brute force infeasible.")


# ─────────────────────────────────────────────
# Goldreich-Levin Hard-Core Predicate
# ─────────────────────────────────────────────
def goldreich_levin_bit(x: int, r: int, n_bits: int) -> int:
    """
    Goldreich-Levin hard-core predicate:
    b(x, r) = <x, r> mod 2  (inner product mod 2 over bit representation)
    
    For our DLP OWF we use a simpler hard-core bit:
    b(x) = LSB(x) — the least significant bit of the discrete log.
    This is the simplest provable hard-core bit for DLP.
    """
    # Inner product of binary representations of x and r mod 2
    inner = bin(x & r).count('1') % 2
    return inner


# ─────────────────────────────────────────────
# PRG from OWF (HILL construction)
# ─────────────────────────────────────────────
class PRG_from_OWF:
    """
    PRG from OWF using iterative hard-core-bit construction:
    G(x0) = b(x0) || b(x1) || ... || b(x_l)
    where x_{i+1} = f(x_i) and b is a hard-core predicate.
    
    Implements: seed(s), next_bits(n)
    """
    def __init__(self, owf: OWF_DLP):
        self.owf = owf
        self._state = None
        self._r = None  # Fixed random string for GL predicate

    def seed(self, s: int):
        """Seed the PRG with initial value s."""
        self._state = s % self.owf.q
        # Fix r for Goldreich-Levin (in practice, r is part of the function's description)
        # For simplicity, use r = all-ones mask of same bit length as q
        bit_len = self.owf.q.bit_length()
        self._r = (1 << bit_len) - 1  # all-ones

    def _next_bit(self) -> int:
        """Compute one pseudorandom bit and advance state."""
        # Hard-core bit: GL inner product
        bit = goldreich_levin_bit(self._state, self._r, self.owf.q.bit_length())
        # Advance: apply OWF
        self._state = self.owf.evaluate(self._state)
        return bit

    def next_bits(self, n: int) -> bytes:
        """
        Generate n pseudorandom bytes.
        Collects bits from the iterative hard-core construction.
        """
        if self._state is None:
            raise RuntimeError("PRG not seeded. Call seed(s) first.")
        bits = []
        for _ in range(n * 8):
            bits.append(self._next_bit())
        # Pack bits into bytes
        result = bytearray()
        for i in range(0, len(bits), 8):
            byte_val = 0
            for j in range(8):
                byte_val = (byte_val << 1) | bits[i + j]
            result.append(byte_val)
        return bytes(result)

    def generate(self, seed_val: int, length_bytes: int) -> bytes:
        """Convenience: seed and generate in one call."""
        self.seed(seed_val)
        return self.next_bits(length_bytes)


# ─────────────────────────────────────────────
# OWF from PRG (backward direction, PA#1b)
# ─────────────────────────────────────────────
class OWF_from_PRG:
    """
    Backward reduction: PRG => OWF.
    Define f(s) = G(s). This is a OWF because:
    - If one could invert G(s) to recover s, that would break PRG security.
    - The seed s is shorter than G(s), so the function is compressing.
    """
    def __init__(self, prg: PRG_from_OWF):
        self.prg = prg

    def evaluate(self, s: int, output_bytes: int = 16) -> bytes:
        """f(s) = G(s)  — maps seed to pseudorandom output."""
        return self.prg.generate(s, output_bytes)

    def demonstrate_hardness(self, num_trials: int = 10):
        """
        Show that given G(s), an adversary cannot recover s efficiently.
        Brute force requires trying all 2^n seeds.
        """
        import time
        seed_space = 1000  # Tiny for demonstration
        target_seed = int.from_bytes(os.urandom(4), 'big') % seed_space
        target_output = self.evaluate(target_seed)
        
        start = time.time()
        found = None
        for guess in range(seed_space):
            if self.evaluate(guess) == target_output:
                found = guess
                break
        elapsed = time.time() - start
        
        print(f"  OWF-from-PRG inversion demo (seed space = {seed_space}):")
        print(f"  Target seed: {target_seed}, Found: {found}")
        print(f"  Time for brute force over {seed_space} seeds: {elapsed*1000:.2f}ms")
        print(f"  For real security parameter n, brute force requires O(2^n) time → infeasible")


# ─────────────────────────────────────────────
# Statistical Tests (NIST SP 800-22 subset)
# ─────────────────────────────────────────────
def bits_from_bytes(data: bytes) -> list:
    """Convert bytes to list of bits."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def test_frequency_monobit(data: bytes) -> dict:
    """
    NIST SP 800-22 Test 1: Frequency (Monobit) Test.
    Count proportion of ones; should be ~0.5 for random data.
    """
    bits = bits_from_bytes(data)
    n = len(bits)
    s_n = sum(1 if b == 1 else -1 for b in bits)
    s_obs = abs(s_n) / math.sqrt(n)
    # P-value using complementary error function
    p_value = math.erfc(s_obs / math.sqrt(2))
    ones_ratio = sum(bits) / n
    return {
        "test": "Frequency (Monobit)",
        "n_bits": n,
        "ones": sum(bits),
        "ones_ratio": ones_ratio,
        "s_obs": s_obs,
        "p_value": p_value,
        "pass": p_value >= 0.01
    }


def test_runs(data: bytes) -> dict:
    """
    NIST SP 800-22 Test 3: Runs Test.
    Count total number of runs (consecutive identical bits).
    """
    bits = bits_from_bytes(data)
    n = len(bits)
    pi = sum(bits) / n

    # Pre-test: check if proportion is not too far from 0.5
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return {"test": "Runs", "pass": False, "reason": "Pre-test failed: proportion too far from 0.5",
                "p_value": 0.0}

    # Count runs
    v_obs = 1
    for i in range(1, n):
        if bits[i] != bits[i - 1]:
            v_obs += 1

    # Compute p-value
    num = abs(v_obs - 2 * n * pi * (1 - pi))
    denom = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(num / denom)

    return {
        "test": "Runs",
        "n_bits": n,
        "runs_observed": v_obs,
        "runs_expected": 2 * n * pi * (1 - pi),
        "p_value": p_value,
        "pass": p_value >= 0.01
    }


def test_serial(data: bytes, m: int = 2) -> dict:
    """
    NIST SP 800-22 Test 11: Serial Test.
    Count frequency of all 2^m bit patterns.
    """
    bits = bits_from_bytes(data)
    n = len(bits)

    def count_patterns(bits, length):
        counts = {}
        for i in range(n):
            pattern = tuple(bits[(i + j) % n] for j in range(length))
            counts[pattern] = counts.get(pattern, 0) + 1
        return counts

    counts_m = count_patterns(bits, m)
    counts_m1 = count_patterns(bits, m - 1)
    counts_m2 = count_patterns(bits, m - 2) if m >= 2 else {}

    def psi_sq(counts, length, n):
        total = sum(v * v for v in counts.values())
        return (2 ** length / n) * total - n

    psi_m = psi_sq(counts_m, m, n)
    psi_m1 = psi_sq(counts_m1, m - 1, n) if m >= 1 else 0
    psi_m2 = psi_sq(counts_m2, m - 2, n) if m >= 2 else 0

    delta1 = psi_m - psi_m1
    delta2 = psi_m - 2 * psi_m1 + psi_m2

    # Chi-squared p-values (simplified)
    def chi2_p(x, df):
        # Regularized incomplete gamma function approximation
        if x <= 0:
            return 1.0
        try:
            return 1.0 - (1.0 - math.exp(-x / 2)) if df == 2 else max(0, 1 - x / (2 * df))
        except:
            return 0.0

    p1 = chi2_p(delta1, 2 ** (m - 2))
    p2 = chi2_p(delta2, 2 ** (m - 3)) if m >= 3 else 1.0

    return {
        "test": f"Serial (m={m})",
        "n_bits": n,
        "delta1": delta1,
        "delta2": delta2,
        "p_value_1": p1,
        "p_value_2": p2,
        "pass": p1 >= 0.01 and p2 >= 0.01
    }


def run_statistical_tests(data: bytes, label: str = ""):
    """Run all three NIST tests and print results."""
    print(f"\n  Statistical Tests{' — ' + label if label else ''}:")
    r1 = test_frequency_monobit(data)
    r2 = test_runs(data)
    r3 = test_serial(data)

    for r in [r1, r2, r3]:
        status = "PASS ✓" if r["pass"] else "FAIL ✗"
        pval = r.get("p_value", r.get("p_value_1", 0))
        print(f"    {r['test']}: {status} (p={pval:.4f})")

    return r1["pass"] and r2["pass"] and r3["pass"]


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #1 — One-Way Functions & Pseudorandom Generators")
    print("=" * 60)

    # 1. Create DLP-based OWF with 64-bit safe prime
    print("\n[1] DLP-based One-Way Function")
    print("  Generating 64-bit safe prime group...")
    owf = OWF_DLP(bits=64)
    print(f"  p = {owf.p}  (safe prime, {owf.p.bit_length()} bits)")
    print(f"  q = {owf.q}  (prime order)")
    print(f"  g = {owf.g}  (generator)")

    x_test = 12345
    y_test = owf.evaluate(x_test)
    print(f"  f({x_test}) = g^{x_test} mod p = {y_test}")
    owf.verify_hardness()

    # 2. PRG from OWF
    print("\n[2] PRG from OWF (HILL iterative hard-core-bit construction)")
    prg = PRG_from_OWF(owf)
    
    seed_val = int.from_bytes(os.urandom(8), 'big') % owf.q
    print(f"  Seed s = {seed_val}")

    output_32 = prg.generate(seed_val, 32)
    print(f"  PRG output (32 bytes): {output_32.hex()}")

    # Test with different lengths
    for length in [16, 32, 64]:
        out = prg.generate(seed_val, length)
        ones = sum(bits_from_bytes(out))
        total = length * 8
        print(f"  Length {length} bytes: {ones}/{total} ones ({100*ones/total:.1f}%)")

    # 3. Statistical tests
    print("\n[3] NIST SP 800-22 Statistical Tests")
    big_output = prg.generate(seed_val, 256)  # 2048 bits
    all_pass = run_statistical_tests(big_output, "PRG output (256 bytes)")
    print(f"  Overall: {'ALL TESTS PASS ✓' if all_pass else 'SOME TESTS FAILED'}")

    # 4. OWF from PRG (backward direction)
    print("\n[4] OWF from PRG (backward direction PA#1b)")
    owf_from_prg = OWF_from_PRG(prg)
    owf_from_prg.demonstrate_hardness()
    print("  Argument: Inverting G(s) recovers seed s,")
    print("  which contradicts PRG pseudorandomness. Therefore G is a OWF.")

    # 5. Determinism: same seed => same output
    print("\n[5] Determinism verification")
    out1 = prg.generate(42, 16)
    out2 = prg.generate(42, 16)
    assert out1 == out2, "PRG must be deterministic!"
    print(f"  PRG(42, 16 bytes) = {out1.hex()}")
    print("  Same seed always gives same output ✓")

    # 6. Different seeds => different outputs
    out3 = prg.generate(43, 16)
    assert out1 != out3, "Different seeds should give different outputs!"
    print(f"  PRG(43, 16 bytes) = {out3.hex()}")
    print("  Different seeds give different outputs ✓")

    print("\n✓ PA #1 complete.")
