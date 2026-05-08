"""
PA #9 — Birthday Attack (Collision Finding)
CS8.401: Principles of Information Security

Implements:
1. Naive birthday algorithm (sort-based)
2. Floyd's cycle detection (space-efficient)
3. Attack on toy hash functions (n=8,12,16 bits)
4. Attack on truncated DLP hash (n=16 bits)
5. Empirical birthday curve for n ∈ {8,10,12,14,16}
6. MD5/SHA-1 context calculations
"""

import os
import sys
import math
import time
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa7_merkle'))
from Q7_merkle_damgard import ToyHash


# ─────────────────────────────────────────────
# Toy Hash with configurable output bits
# ─────────────────────────────────────────────
def make_toy_hash(n_bits: int):
    """
    Create a toy hash function with n_bits output.
    Uses truncated XOR-based MD construction.
    """
    from Q7_merkle_damgard import MerkleDamgard, toy_compress_xor, md_pad
    import struct

    n_bytes = max(1, n_bits // 8)
    
    def truncated_compress(cv: bytes, block: bytes) -> bytes:
        """XOR-fold compression, output n_bytes."""
        # Ensure cv and block are same length
        blen = 8
        if len(block) < blen:
            block = block + b'\x00' * (blen - len(block))
        block = block[:blen]
        if len(cv) < 4:
            cv = cv + b'\x00' * (4 - len(cv))
        cv = cv[:4]
        result = toy_compress_xor(cv, block)
        # Truncate to n_bytes, then mask to n_bits
        result = result[:n_bytes]
        if n_bits % 8 != 0:
            mask = (1 << (n_bits % 8)) - 1
            result = bytes([result[0] & mask]) + result[1:]
        return result

    iv = b'\x5a' * n_bytes
    if n_bits % 8 != 0:
        iv = bytes([iv[0] & ((1 << (n_bits % 8)) - 1)]) + iv[1:]
    
    md = MerkleDamgard(truncated_compress, iv, block_size=8)
    
    def hash_fn(msg: bytes) -> bytes:
        return md.hash(msg)
    
    return hash_fn


# ─────────────────────────────────────────────
# 1. Naive Birthday Algorithm
# ─────────────────────────────────────────────
def birthday_attack(hash_fn, n_bits: int, max_trials: int = None) -> tuple:
    """
    Naive birthday attack: hash random inputs, store in dictionary,
    find first collision.
    
    hash_fn: callable bytes -> bytes
    n_bits: output bit length (for expected cost estimation)
    Returns: (x1, x2, hash_value, evaluations_count)
    """
    if max_trials is None:
        max_trials = max(10 * int(2 ** (n_bits / 2)), 10000)
    
    seen = {}
    for count in range(1, max_trials + 1):
        x = os.urandom(max(4, n_bits // 4))
        h = hash_fn(x)
        if h in seen and seen[h] != x:
            return (seen[h], x, h, count)
        seen[h] = x
    return None


# ─────────────────────────────────────────────
# 2. Floyd's Cycle Detection
# ─────────────────────────────────────────────
def floyd_birthday_attack(hash_fn, n_bits: int, seed: bytes = None) -> tuple:
    """
    Space-efficient birthday attack using Floyd's tortoise-and-hare.
    Treats hash as f: {0,1}^n -> {0,1}^n.
    
    Returns: (x1, x2, hash_value, evaluations_count) or None
    """
    n_bytes = max(1, n_bits // 8)
    
    def f(x: bytes) -> bytes:
        """Function: hash output as input for next step."""
        h = hash_fn(x)
        # Normalize to n_bytes
        if len(h) < n_bytes:
            h = h + b'\x00' * (n_bytes - len(h))
        return h[:n_bytes]
    
    # Start
    if seed is None:
        seed = os.urandom(n_bytes)
    
    # Phase 1: Find meeting point (tortoise moves 1 step, hare moves 2)
    tortoise = f(seed)
    hare = f(f(seed))
    count = 2
    
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(f(hare))
        count += 2
        if count > 2 ** (n_bits + 2):
            return None  # Give up

    # Phase 2: Find start of cycle (lambda)
    mu = 0
    tortoise = seed
    while tortoise != hare:
        tortoise = f(tortoise)
        hare = f(hare)
        mu += 1
        count += 2

    # Phase 3: Find cycle length (lambda)
    lam = 1
    hare = f(tortoise)
    count += 1
    while tortoise != hare:
        hare = f(hare)
        lam += 1
        count += 1

    # Now we have cycle start (mu) and length (lam)
    # x1 = f^{mu}(seed), x2 = f^{mu + lam}(seed)
    x1 = seed
    for _ in range(mu):
        x1 = f(x1)

    x2 = x1
    for _ in range(lam):
        x2 = f(x2)

    # Verify collision: hash(x1) == hash(x2) but inputs to hash differ
    h1 = hash_fn(x1)
    h2 = hash_fn(x2)
    
    if x1 != x2 and h1 == h2:
        return (x1, x2, h1, count)
    return None


# ─────────────────────────────────────────────
# 3. Attack Toy Hash
# ─────────────────────────────────────────────
def attack_toy_hash(n_bits: int) -> dict:
    """Run birthday attack on toy hash with n_bits output."""
    hash_fn = make_toy_hash(n_bits)
    expected = 2 ** (n_bits / 2)
    
    result = birthday_attack(hash_fn, n_bits)
    if result:
        x1, x2, h, evals = result
        return {
            'n_bits': n_bits,
            'x1': x1.hex(),
            'x2': x2.hex(),
            'hash': h.hex(),
            'evaluations': evals,
            'expected': expected,
            'ratio': evals / expected,
        }
    return {'n_bits': n_bits, 'evaluations': None}


# ─────────────────────────────────────────────
# 4. Attack Truncated DLP Hash
# ─────────────────────────────────────────────
def attack_dlp_hash_truncated(n_bits: int = 16) -> dict:
    """Attack truncated DLP hash to confirm birthday bound."""
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa8_dlp_hash'))
    from Q8_dlp_hash import DLP_Hash, DLPHashParams
    
    print(f"  Generating DLP hash parameters (may take a moment)...")
    params = DLPHashParams(bits=64)
    dlp = DLP_Hash(params)
    
    def truncated_dlp(msg: bytes) -> bytes:
        h = dlp.hash(msg)
        # Truncate to n_bits
        n_bytes = max(1, n_bits // 8)
        result = h[:n_bytes]
        if n_bits % 8 != 0:
            mask = (1 << (n_bits % 8)) - 1
            result = bytes([result[0] & mask]) + result[1:]
        return result
    
    expected = 2 ** (n_bits / 2)
    result = birthday_attack(truncated_dlp, n_bits)
    
    if result:
        x1, x2, h, evals = result
        return {
            'n_bits': n_bits,
            'x1': x1.hex(),
            'x2': x2.hex(),
            'hash': h.hex(),
            'evaluations': evals,
            'expected': expected,
            'ratio': evals / expected,
        }
    return {'n_bits': n_bits, 'evaluations': None}


# ─────────────────────────────────────────────
# 5. Empirical Birthday Curve
# ─────────────────────────────────────────────
def empirical_birthday_curve(n_values=None, trials_per_n: int = 20) -> dict:
    """
    Run trials for each n in n_values.
    Returns dict: n -> list of evaluation counts until collision.
    """
    if n_values is None:
        n_values = [8, 10, 12, 14, 16]
    
    results = {}
    for n in n_values:
        hash_fn = make_toy_hash(n)
        counts = []
        for _ in range(trials_per_n):
            r = birthday_attack(hash_fn, n)
            if r:
                counts.append(r[3])
        results[n] = counts
    return results


def theoretical_birthday_probability(k: int, n_bits: int) -> float:
    """P(collision by k-th hash) ≈ 1 - e^(-k(k-1)/2^(n+1))."""
    N = 2 ** n_bits
    return 1.0 - math.exp(-k * (k - 1) / (2 * N))


# ─────────────────────────────────────────────
# 6. MD5/SHA-1 Context
# ─────────────────────────────────────────────
def md5_sha1_context():
    """Calculate 2^(n/2) for MD5 (n=128) and SHA-1 (n=160)."""
    print("\n  MD5/SHA-1 Birthday Bound Context:")
    cpu_speed = 1e9  # 10^9 hash/sec (modern CPU)
    
    for name, n in [("MD5", 128), ("SHA-1", 160), ("SHA-256", 256)]:
        ops = 2 ** (n / 2)
        seconds = ops / cpu_speed
        years = seconds / (365.25 * 24 * 3600)
        
        if years > 1e15:
            time_str = f"~{years:.2e} years (practically infeasible)"
        elif years > 1e6:
            time_str = f"~{years:.2e} years"
        elif years > 1:
            time_str = f"~{years:.2e} years"
        else:
            time_str = f"~{seconds:.2e} seconds"
        
        print(f"  {name} (n={n}): 2^{n/2:.0f} ≈ {ops:.2e} ops → {time_str}")
        if n <= 160:
            print(f"    → BROKEN (collision attacks demonstrated in practice)")
        else:
            print(f"    → Currently secure")


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #9 — Birthday Attack (Collision Finding)")
    print("=" * 60)

    # 1. Naive birthday on toy hashes
    print("\n[1] Naive Birthday Attack on Toy Hash Functions")
    for n in [8, 10, 12]:
        r = attack_toy_hash(n)
        if r['evaluations']:
            print(f"  n={n} bits: collision at {r['evaluations']} evals "
                  f"(expected ≈{r['expected']:.1f}, ratio={r['ratio']:.2f})")
            print(f"    x1={r['x1']}, x2={r['x2']}, H={r['hash']}")
        else:
            print(f"  n={n} bits: no collision found")

    # 2. Floyd's cycle detection
    print("\n[2] Floyd's Cycle Detection (Space-Efficient)")
    for n in [8, 10]:
        hash_fn = make_toy_hash(n)
        r = floyd_birthday_attack(hash_fn, n)
        if r:
            x1, x2, h, count = r
            expected = 2 ** (n / 2)
            print(f"  n={n} bits: Floyd found collision at ~{count} evals "
                  f"(expected ≈{expected:.1f})")
            print(f"    hash(x1) = hash(x2) = {h.hex()} ✓")
        else:
            print(f"  n={n} bits: Floyd - no collision found")

    # 3. Empirical birthday curve
    print("\n[3] Empirical Birthday Curve (20 trials per n)")
    results = empirical_birthday_curve([8, 10, 12], trials_per_n=20)
    print(f"  {'n':>4} | {'mean evals':>12} | {'2^(n/2)':>10} | ratio")
    print(f"  {'-'*45}")
    for n, counts in sorted(results.items()):
        if counts:
            mean = sum(counts) / len(counts)
            expected = 2 ** (n / 2)
            print(f"  {n:>4} | {mean:>12.1f} | {expected:>10.1f} | {mean/expected:.2f}")

    # 4. Truncated DLP hash
    print("\n[4] Birthday Attack on Truncated DLP Hash (n=16 bits)")
    print("  (This may take a moment...)")
    r = attack_dlp_hash_truncated(n_bits=16)
    if r.get('evaluations'):
        print(f"  Collision at {r['evaluations']} evals (expected ≈{r['expected']:.1f})")
        print(f"  x1 = {r['x1']}")
        print(f"  x2 = {r['x2']}")
        print(f"  H(x1) = H(x2) = {r['hash']}")
        print(f"  Ratio (actual/expected): {r['ratio']:.2f}")
        print("  DLP hash at 16-bit output is broken at birthday bound ✓")

    # 5. MD5/SHA-1 context
    md5_sha1_context()

    print("\n[6] Birthday Probability Formula: P(k, n) = 1 - e^(-k^2/2^n)")
    print("  k    | P(k, n=12) | P(k, n=16) | P(k, n=20)")
    print("  " + "-"*50)
    for k in [1, 10, 64, 100, 256, 512]:
        p12 = theoretical_birthday_probability(k, 12)
        p16 = theoretical_birthday_probability(k, 16)
        p20 = theoretical_birthday_probability(k, 20)
        print(f"  {k:>5}| {p12:>10.4f} | {p16:>10.4f} | {p20:>10.4f}")

    print("\n✓ PA #9 complete.")
