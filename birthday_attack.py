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
from merkle_damgard import ToyHash


# ─────────────────────────────────────────────
# Toy Hash with configurable output bits
# ─────────────────────────────────────────────
def make_toy_hash(n_bits: int):
    """
    Create a toy hash function with n_bits output.
    Uses truncated XOR-based MD construction.
    """
    from merkle_damgard import toy_compress_xor, MerkleDamgard, md_pad
    import struct

    n_bytes = (n_bits + 7) // 8  # Ceiling division: 10 bits -> 2 bytes
    
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
    
    Algorithm:
    1. Phase 1: tortoise-and-hare to detect cycle.
    2. Phase 2: find collision at cycle entry — look for two distinct
       inputs that map to the same output: f(a) == f(b) but a != b.
    
    Returns: (x1, x2, hash_value, evaluations_count) or None
    """
    n_bytes = (n_bits + 7) // 8
    
    def f(x: bytes) -> bytes:
        """Function: hash output as input for next step."""
        h = hash_fn(x)
        # Normalize to n_bytes
        if len(h) < n_bytes:
            h = h + b'\x00' * (n_bytes - len(h))
        return h[:n_bytes]
    
    max_attempts = 5
    for attempt in range(max_attempts):
        x0 = seed if (seed is not None and attempt == 0) else os.urandom(n_bytes)
        
        # Phase 1: Find meeting point (tortoise moves 1, hare moves 2)
        tortoise = f(x0)
        hare = f(f(x0))
        count = 3  # 3 calls to f
        
        max_steps = 4 * (2 ** n_bits)
        while tortoise != hare:
            tortoise = f(tortoise)
            hare = f(f(hare))
            count += 3
            if count > max_steps:
                break
        
        if tortoise != hare:
            continue  # retry with different seed
        
        # Phase 2: Find the collision.
        # Reset tortoise to x0. Walk both one step at a time.
        # Look for f(tortoise) == f(hare) while tortoise != hare.
        # This occurs one step before the cycle entry point.
        tortoise = x0
        
        while True:
            next_t = f(tortoise)
            next_h = f(hare)
            count += 2
            
            if next_t == next_h:
                if tortoise != hare:
                    # Found collision: f(tortoise) = f(hare), tortoise != hare
                    return (tortoise, hare, next_t, count)
                else:
                    # mu = 0: both at same position, try different seed
                    break
            
            tortoise = next_t
            hare = next_h
    
    return None  # All attempts failed


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
    from dlp_hash import DLP_Hash, DLPHashParams
    
    print(f"  Generating DLP hash parameters (may take a moment)...")
    params = DLPHashParams(bits=64)
    dlp = DLP_Hash(params)
    
    def truncated_dlp(msg: bytes) -> bytes:
        h = dlp.hash(msg)
        # Truncate to n_bits
        n_bytes = (n_bits + 7) // 8
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


def theoretical_birthday_probability_cdf(k: int, n_bits: int) -> float:
    """P(collision by k-th hash) ≈ 1 - e^(-k(k-1)/2^(n+1))."""
    N = 2 ** n_bits
    return 1.0 - math.exp(-k * (k - 1) / (2 * N))


def theoretical_birthday_probability_demo(k: int, n_bits: int) -> float:
    """Demo curve: 1 - e^(-k^2/2^n)"""
    N = 2 ** n_bits
    return 1.0 - math.exp(-(k * k) / N)


def plot_toy_hash_results(results: list, out_path: str) -> None:
    """Plot empirical evaluations vs theoretical 2^(n/2)."""
    import matplotlib.pyplot as plt

    ns = [r['n_bits'] for r in results if r.get('evaluations')]
    actual = [r['evaluations'] for r in results if r.get('evaluations')]
    expected = [r['expected'] for r in results if r.get('evaluations')]

    plt.figure(figsize=(6.5, 4))
    plt.plot(ns, expected, marker='o', color='#fbbf24', label='2^(n/2) expected')
    plt.scatter(ns, actual, color='#22d3ee', label='Empirical evals')
    plt.title('Birthday Attack: Toy Hash Evaluations')
    plt.xlabel('Output bits n')
    plt.ylabel('Evaluations until collision')
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


def plot_empirical_birthday_curve(results: dict, out_path: str) -> None:
    """Plot empirical CDFs with theoretical overlay for each n."""
    import matplotlib.pyplot as plt

    n_values = sorted(results.keys())
    cols = 2
    rows = (len(n_values) + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(10, 4.5 * rows))
    axes_flat = axes.flatten() if hasattr(axes, 'flatten') else [axes]

    for ax, n in zip(axes_flat, n_values):
        counts = sorted(results[n])
        if not counts:
            ax.set_title(f'n={n} (no data)')
            continue
        m = len(counts)
        ys = [(i + 1) / m for i in range(m)]
        ax.step(counts, ys, where='post', label='Empirical CDF')

        max_k = max(counts)
        ks = list(range(1, max_k + 1))
        theory = [theoretical_birthday_probability_cdf(k, n) for k in ks]
        ax.plot(ks, theory, color='#fbbf24', label='Theory')

        expected = 2 ** (n / 2)
        ax.axvline(expected, color='#22d3ee', linestyle='--', label='2^(n/2)')
        ax.set_title(f'n={n} bits')
        ax.set_xlabel('Evaluations (k)')
        ax.set_ylabel('P(collision by k)')
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=8)

    # Hide unused axes
    for ax in axes_flat[len(n_values):]:
        ax.axis('off')

    plt.tight_layout()
    plt.savefig(out_path)
    plt.close()


# ─────────────────────────────────────────────
# 6. MD5/SHA-1 Context
# ─────────────────────────────────────────────
def md5_sha1_context():
    """Calculate 2^(n/2) for MD5 (n=128) and SHA-1 (n=160)."""
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
    toy_results = []
    for n in [8, 12, 16]:
        r = attack_toy_hash(n)
        toy_results.append(r)
        if r['evaluations']:
            print(f"  n={n} bits: collision at {r['evaluations']} evals "
                  f"(expected ≈{r['expected']:.1f}, ratio={r['ratio']:.2f})")
            print(f"    x1={r['x1']}, x2={r['x2']}, H={r['hash']}")
        else:
            print(f"  n={n} bits: no collision found")

    toy_plot_path = os.path.join(os.path.dirname(__file__), 'toy_hash_plot.png')
    plot_toy_hash_results(toy_results, toy_plot_path)
    print(f"  Plot saved to {toy_plot_path}")

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
    print("\n[3] Empirical Birthday Curve (100 trials per n)")
    results = empirical_birthday_curve([8, 10, 12, 14, 16], trials_per_n=100)
    print(f"  {'n':>4} | {'mean evals':>12} | {'2^(n/2)':>10} | ratio")
    print(f"  {'-'*45}")
    for n, counts in sorted(results.items()):
        if counts:
            mean = sum(counts) / len(counts)
            expected = 2 ** (n / 2)
            print(f"  {n:>4} | {mean:>12.1f} | {expected:>10.1f} | {mean/expected:.2f}")

    curve_plot_path = os.path.join(os.path.dirname(__file__), 'birthday_curve.png')
    plot_empirical_birthday_curve(results, curve_plot_path)
    print(f"  Plot saved to {curve_plot_path}")

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
    print("\n[5] MD5/SHA-1 Birthday Bound Context")
    md5_sha1_context()

    # 6. Birthday probability table
    print("\n[6] Birthday Probability Formula: P(k, n) = 1 - e^(-k^2/2^n)")
    print("  k    | P(k, n=12) | P(k, n=16) | P(k, n=20)")
    print("  " + "-"*50)
    for k in [1, 10, 64, 100, 256, 512]:
        p12 = theoretical_birthday_probability_demo(k, 12)
        p16 = theoretical_birthday_probability_demo(k, 16)
        p20 = theoretical_birthday_probability_demo(k, 20)
        print(f"  {k:>5}| {p12:>10.4f} | {p16:>10.4f} | {p20:>10.4f}")

    print("\n✓ PA #9 complete.")
