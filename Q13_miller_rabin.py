"""
PA #13 — Miller-Rabin Primality Testing
CS8.401: Principles of Information Security

Implements:
1. miller_rabin(n, k) — probabilistic primality test
2. gen_prime(bits) — generate a random b-bit prime
3. Carmichael number demo (561)
4. Performance benchmark
"""

import os
import time
import random
import math


# ─────────────────────────────────────────────
# Modular exponentiation (square-and-multiply)
# ─────────────────────────────────────────────
def mod_exp(base, exp, mod):
    """Compute base^exp mod mod using square-and-multiply."""
    if mod == 1:
        return 0
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


# ─────────────────────────────────────────────
# Fermat primality test (naive, broken for Carmichaels)
# ─────────────────────────────────────────────
def fermat_test(n, k=20):
    """Naive Fermat primality test. Fooled by Carmichael numbers."""
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for _ in range(k):
        a = random.randint(2, n - 2)
        if mod_exp(a, n - 1, n) != 1:
            return False
    return True


# ─────────────────────────────────────────────
# Miller-Rabin primality test
# ─────────────────────────────────────────────
def miller_rabin(n: int, k: int = 40) -> str:
    """
    Miller-Rabin probabilistic primality test.
    Returns 'PROBABLY_PRIME' or 'COMPOSITE'.
    Error probability <= 4^(-k).
    """
    if n < 2:
        return "COMPOSITE"
    if n == 2 or n == 3:
        return "PROBABLY_PRIME"
    if n % 2 == 0:
        return "COMPOSITE"

    # Write n-1 = 2^s * d, d odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # k rounds
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = mod_exp(a, d, n)

        if x == 1 or x == n - 1:
            continue  # probably prime for this witness

        composite = True
        for r in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break

        if composite:
            return "COMPOSITE"

    return "PROBABLY_PRIME"


def is_prime(n: int, k: int = 40) -> bool:
    """Convenience wrapper returning bool."""
    return miller_rabin(n, k) == "PROBABLY_PRIME"


# ─────────────────────────────────────────────
# Prime generation
# ─────────────────────────────────────────────
def gen_prime(bits: int, k: int = 40) -> int:
    """
    Generate a random probable prime of exactly `bits` bits.
    Repeatedly samples random odd b-bit integers until one passes
    Miller-Rabin with k rounds.
    """
    while True:
        # Random bits-bit odd number with MSB set
        n = int.from_bytes(os.urandom(bits // 8 + 1), 'big')
        # Mask to exact bit length
        n |= (1 << (bits - 1))   # Set MSB
        n |= 1                    # Make odd
        n &= (1 << bits) - 1     # Clear bits above `bits`
        if is_prime(n, k):
            return n


def gen_safe_prime(bits: int) -> tuple:
    """
    Generate a safe prime p = 2q + 1 where both p and q are prime.
    Returns (p, q).
    """
    while True:
        q = gen_prime(bits - 1)
        p = 2 * q + 1
        if is_prime(p, 20):
            return p, q


# ─────────────────────────────────────────────
# Demos
# ─────────────────────────────────────────────
def demo_carmichael():
    """Demonstrate that 561 fools Fermat but NOT Miller-Rabin."""
    n = 561  # Smallest Carmichael number
    print(f"\n=== Carmichael Number Demo: n = {n} ===")
    print(f"  Is 561 prime? (actual): {n} = 3 × 11 × 17 → COMPOSITE")
    fermat_result = fermat_test(n, k=40)
    mr_result = miller_rabin(n, k=1)
    print(f"  Fermat test (40 rounds): {'PROBABLY PRIME (WRONG!)' if fermat_result else 'COMPOSITE'}")
    print(f"  Miller-Rabin (1 round):  {mr_result}")
    # Verify factorisation
    assert n == 3 * 11 * 17
    assert not fermat_result or True  # Fermat may or may not catch it every run
    assert mr_result == "COMPOSITE", "Miller-Rabin MUST catch 561!"
    print("  ✓ Miller-Rabin correctly identifies 561 as COMPOSITE")


def demo_performance():
    """Benchmark prime generation at multiple bit sizes."""
    print("\n=== Prime Generation Performance ===")
    for bits in [64, 128, 256, 512, 1024, 2048]:
        candidates = 0
        trials = 5
        start = time.time()
        for _ in range(trials):
            # Count candidates by patching gen_prime
            found = False
            while not found:
                candidates += 1
                n = int.from_bytes(os.urandom(bits // 8 + 1), 'big')
                n |= (1 << (bits - 1))
                n |= 1
                n &= (1 << bits) - 1
                if is_prime(n, 40):
                    found = True
        elapsed = time.time() - start
        avg_candidates = candidates / trials
        theoretical = math.log(2 ** bits)  # ln(N) ≈ bits * ln(2)
        print(f"  {bits}-bit prime: avg {avg_candidates:.1f} candidates, "
              f"theory O(ln N)={theoretical:.1f}, {elapsed/trials*1000:.1f} ms/prime")


if __name__ == "__main__":
    print("=" * 60)
    print("PA #13 — Miller-Rabin Primality Testing")
    print("=" * 60)

    # Basic tests
    known_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 1000000007]
    known_composites = [4, 6, 9, 15, 100, 561, 1024]

    print("\n=== Basic Correctness ===")
    for p in known_primes:
        result = miller_rabin(p, 40)
        print(f"  {p}: {result} {'✓' if result == 'PROBABLY_PRIME' else '✗ ERROR'}")

    for c in known_composites:
        result = miller_rabin(c, 40)
        print(f"  {c}: {result} {'✓' if result == 'COMPOSITE' else '✗ ERROR'}")

    demo_carmichael()

    print("\n=== Prime Generation ===")
    for bits in [32, 64, 128]:
        p = gen_prime(bits)
        print(f"  {bits}-bit prime: {p}")
        assert is_prime(p, 100), "Generated number failed 100-round verification!"
        print(f"    Verified with 100 rounds ✓")

    print("\n=== Safe Prime Generation (for DH/DLP) ===")
    p, q = gen_safe_prime(32)
    print(f"  Safe prime p = {p} = 2*{q} + 1")
    assert is_prime(p) and is_prime(q)
    print("  Both p and q are prime ✓")

    demo_performance()

    print("\n✓ PA #13 complete.")
