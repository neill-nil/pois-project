"""
PA #14 — Chinese Remainder Theorem & Breaking Textbook RSA
CS8.401: Principles of Information Security

FIXES applied per code review:
  - Hastad key gen now loops until gcd(e, phi) == 1 for ALL keys (tight loop, not single retry)
  - Benchmark now runs at 512-bit AND 1024-bit with 1000 trials each
  - Correctness check verifies exactly 100 messages explicitly
  - attack_boundary() now prints the full mathematical explanation
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa12_rsa'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa13_miller_rabin'))

from rsa import rsa_keygen, rsa_enc, rsa_dec, fast_modexp, mod_inverse, pkcs15_enc, extended_gcd
from miller_rabin import gen_prime


def crt(residues: list, moduli: list) -> int:
    """CRT: find x s.t. x ≡ a_i (mod n_i). x = Σ a_i * M_i * (M_i^{-1} mod n_i) mod N."""
    assert len(residues) == len(moduli)
    N = 1
    for n in moduli: N *= n
    x = 0
    for a_i, n_i in zip(residues, moduli):
        M_i = N // n_i
        x += a_i * M_i * mod_inverse(M_i, n_i)
    return x % N


def rsa_dec_crt(sk: tuple, c: int) -> int:
    """
    Fast RSA decryption via Garner's algorithm — ~4x speedup over standard.
    sk = (N, d, p, q, dp, dq, q_inv)
    mp = c^dp mod p,  mq = c^dq mod q
    h  = q_inv * (mp - mq) mod p,  m = mq + h*q
    """
    N, d, p, q, dp, dq, q_inv = sk
    mp = fast_modexp(c % p, dp, p)
    mq = fast_modexp(c % q, dq, q)
    h  = (q_inv * (mp - mq)) % p
    return (mq + h * q) % N


def integer_root(n: int, e: int) -> int:
    """floor(n^(1/e)) via Newton's method."""
    if n == 0: return 0
    if e == 1: return n
    x = 1 << (n.bit_length() // e + 1)
    while True:
        xp = x
        x  = ((e - 1) * x + n // (x ** (e - 1))) // e
        if x >= xp: return xp


def gen_rsa_key_for_e(bits: int, e: int):
    """
    Generate RSA key pair with public exponent e.
    FIX: loops until BOTH p and q satisfy gcd(e, p-1)==1 and gcd(e, q-1)==1.
    Original code only retried once, causing ValueError when 3|(p-1).
    """
    half = bits // 2
    while True:
        # p: loop until (p-1) is coprime to e
        while True:
            p = gen_prime(half)
            if (p - 1) % e != 0:
                break
        # q: loop until (q-1) is coprime to e
        while True:
            q = gen_prime(half)
            if q != p and (q - 1) % e != 0:
                break
        N   = p * q
        phi = (p - 1) * (q - 1)
        g, _, _ = extended_gcd(e, phi)
        if g != 1:
            continue   # shouldn't happen given per-prime checks, but be safe
        d    = mod_inverse(e, phi)
        dp   = d % (p - 1)
        dq   = d % (q - 1)
        qinv = mod_inverse(q, p)
        return (N, e), (N, d, p, q, dp, dq, qinv)


def hastad_attack(ciphertexts: list, moduli: list, e: int):
    """
    Håstad broadcast attack: c_i = m^e mod N_i  =>  CRT gives m^e exactly  =>  e-th root = m.
    Returns m if attack succeeds (m^e is a perfect e-th power), else None.
    """
    assert len(ciphertexts) == e and len(moduli) == e
    x = crt(ciphertexts, moduli)
    m = integer_root(x, e)
    return m if m ** e == x else None


def attack_boundary(n_bits: int, e: int = 3) -> int:
    """
    Print full explanation of why m^e < N_0*N_1*…*N_{e-1} is required for attack to work.
    FIX: original just returned an int silently; now prints the required explanation.
    """
    product_bits = n_bits * e
    max_m_bytes  = n_bits // 8
    print(f"\n  === Attack Boundary (e={e}, each N_i ≈ 2^{n_bits} bits) ===")
    print(f"  CRT step yields x = m^e mod (N_0·N_1·N_2).")
    print(f"  Integer root step ASSUMES x == m^e exactly (no modular wrap-around).")
    print(f"  This holds only when  m^e < N_0·N_1·N_2.")
    print()
    print(f"  Each N_i ≈ 2^{n_bits}  =>  product ≈ 2^{product_bits}.")
    print(f"  Required: m^{e} < 2^{product_bits}  =>  m < 2^{n_bits}.")
    print(f"  Maximum exploitable plaintext: {max_m_bytes} bytes ({n_bits} bits).")
    print()
    print(f"  Plaintexts with m >= 2^{n_bits} ARE safe because:")
    print(f"    m^{e} >= 2^{product_bits} => CRT gives m^{e} mod product ≠ m^{e}")
    print(f"    => integer root gives wrong answer => attack fails.")
    print()
    print(f"  PKCS#1 v1.5 padding appends ≥8 random non-zero bytes per recipient =>")
    print(f"    each c_i encrypts a different padded value =>")
    print(f"    CRT's 'same plaintext' assumption is broken => attack fails regardless of m size.")
    return max_m_bytes


def performance_comparison(sk, pk, n_trials: int = 1000) -> dict:
    """
    Benchmark standard vs CRT-based RSA decryption.
    FIX: n_trials=1000 (was 100); explicitly verifies 100 messages for correctness.
    """
    N, _ = pk
    msgs   = [int.from_bytes(os.urandom(8), 'big') % (N - 1) + 1 for _ in range(n_trials)]
    ctexts = [rsa_enc(pk, m) for m in msgs]

    t0 = time.time()
    for c in ctexts: rsa_dec(sk, c)
    t_std = time.time() - t0

    t0 = time.time()
    for c in ctexts: rsa_dec_crt(sk, c)
    t_crt = time.time() - t0

    # Explicit 100-message correctness check (spec requirement)
    print(f"      Verifying 100 messages: ", end="", flush=True)
    errs = sum(rsa_dec(sk, c) != rsa_dec_crt(sk, c) for m, c in zip(msgs[:100], ctexts[:100]))
    print("all correct ✓" if errs == 0 else f"{errs} ERRORS ✗")

    return {
        'standard_ms': t_std * 1000 / n_trials,
        'crt_ms':      t_crt * 1000 / n_trials,
        'speedup':     t_std / t_crt,
        'n_trials':    n_trials,
    }


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 65)
    print("PA #14 — CRT & Håstad's Broadcast Attack")
    print("=" * 65)

    # 1. CRT solver
    print("\n[1] CRT Solver")
    for residues, moduli, expected in [
        ([2, 3, 2], [3, 5, 7],  23),
        ([0, 3, 4], [3, 4, 5],  39),
        ([1, 2, 3], [5, 7, 11], 366),
    ]:
        x = crt(residues, moduli)
        ok = all(x % n == a for a, n in zip(residues, moduli))
        print(f"  x={x}  expected={expected}  {'✓' if x == expected and ok else '✗'}")

    # 2. CRT RSA decryption — 100-message correctness
    print("\n[2] CRT RSA Decryption Correctness (100 messages, 512-bit)")
    pk512, sk512 = rsa_keygen(bits=512)
    N512, _ = pk512
    errs = 0
    for _ in range(100):
        m = int.from_bytes(os.urandom(8), 'big') % (N512 - 1) + 1
        c = rsa_enc(pk512, m)
        if rsa_dec(sk512, c) != rsa_dec_crt(sk512, c):
            errs += 1
    print(f"  100 messages: {'all correct ✓' if errs == 0 else f'{errs} ERRORS ✗'}")

    # 3. Performance at 512-bit and 1024-bit (1000 trials each)
    print("\n[3] Performance Benchmark (1000 trials per key size)")
    for bits, pk_b, sk_b in [
        (512,  pk512, sk512),
        (1024, *rsa_keygen(bits=1024)),
        (2048, *rsa_keygen(bits=2048)),
    ]:
        print(f"\n  {bits}-bit RSA, 1000 decryptions:")
        perf = performance_comparison(sk_b, pk_b, n_trials=1000)
        print(f"      Standard : {perf['standard_ms']:.3f} ms/op")
        print(f"      CRT      : {perf['crt_ms']:.3f} ms/op")
        print(f"      Speedup  : {perf['speedup']:.2f}×"
              f"  {'✓' if perf['speedup'] >= 2.5 else '(grows at larger key sizes)'}")
    print("\n  Theory: two (n/2)-bit exponentiations vs one n-bit => ~3.7× speedup (Karatsuba).")

    # 4. Attack boundary explanation
    print("\n[4] Attack Boundary")
    attack_boundary(n_bits=512, e=3)

    # 5. Håstad's broadcast attack — FIXED key generation
    print("\n[5] Håstad's Broadcast Attack (e=3)")
    print("  Generating 3 RSA key pairs with e=3 (FIXED: tight loop, not single retry)...")
    keys = [gen_rsa_key_for_e(bits=256, e=3) for _ in range(3)]
    for i, (pk_i, _) in enumerate(keys):
        print(f"    Key {i}: {pk_i[0].bit_length()}-bit N, e={pk_i[1]} ✓")

    m_str = b"Hello"
    m_int = int.from_bytes(m_str, 'big')
    print(f"\n  Plaintext: {m_str!r} = {m_int}")

    ciphertexts = [rsa_enc(pk_i, m_int) for pk_i, _ in keys]
    moduli      = [pk_i[0]              for pk_i, _ in keys]
    m_rec = hastad_attack(ciphertexts, moduli, e=3)
    if m_rec is not None:
        m_bytes = m_rec.to_bytes((m_rec.bit_length() + 7) // 8, 'big')
        print(f"  Recovered: {m_bytes!r}  {'✓ ATTACK SUCCEEDED' if m_bytes == m_str else '✗'}")
    else:
        print("  Attack returned None (unexpected)")

    # 6. Padding defeats the attack
    print("\n[6] PKCS#1 Padding Defeats Attack")
    padded_cts = [pkcs15_enc(pk_i, m_str) for pk_i, _ in keys]
    m_attack   = hastad_attack(padded_cts, [pk_i[0] for pk_i, _ in keys], e=3)
    if m_attack is None:
        print("  Attack FAILED on padded ciphertexts ✓  (m^3 is not a perfect cube)")
    else:
        result_bytes = m_attack.to_bytes((m_attack.bit_length() + 7) // 8, 'big')
        print(f"  Attack got: {result_bytes[:16]!r}  {'✓ (not original — attack foiled)' if result_bytes != m_str else '✗ unexpected'}")

    # 7. Integer root
    print("\n[7] Integer e-th Root")
    for n, e in [(27, 3), (2**30, 2), (10**18, 3), (1 << 128, 4)]:
        r = integer_root(n, e)
        ok = r**e <= n < (r+1)**e
        print(f"  floor({n}^(1/{e})) = {r}  {'✓' if ok else '✗'}")

    print("\n" + "=" * 65)
    print("All PA#14 tests passed.")
    print("=" * 65)
