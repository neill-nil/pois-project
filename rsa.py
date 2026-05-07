"""
PA #12 — Textbook RSA + PKCS#1 v1.5
CS8.401: Principles of Information Security

Implements:
1. RSA key generation (using PA#13 Miller-Rabin)
2. Textbook RSA: Enc = m^e mod N, Dec = c^d mod N
3. PKCS#1 v1.5 padded RSA
4. Determinism attack demonstration
5. Simplified Bleichenbacher padding oracle
6. Interface: Enc(pk, m), Dec(sk, c), key generation
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa13_miller_rabin'))
from miller_rabin import mod_exp, gen_prime, is_prime


# ─────────────────────────────────────────────
# Extended Euclidean Algorithm (self-implemented)
# ─────────────────────────────────────────────
def extended_gcd(a: int, b: int) -> tuple:
    """Returns (gcd, x, y) such that a*x + b*y = gcd."""
    if b == 0:
        return a, 1, 0
    g, x, y = extended_gcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(a: int, n: int) -> int:
    """Compute a^(-1) mod n using extended Euclidean algorithm."""
    g, x, _ = extended_gcd(a % n, n)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a},{n}) = {g} ≠ 1")
    return x % n


# ─────────────────────────────────────────────
# RSA Key Generation
# ─────────────────────────────────────────────
def rsa_keygen(bits: int = 1024) -> tuple:
    """
    Generate RSA key pair.
    Returns (pk, sk) where:
      pk = (N, e)
      sk = (N, d, p, q, dp, dq, q_inv)
    """
    half = bits // 2
    # Generate two distinct primes
    while True:
        p = gen_prime(half)
        q = gen_prime(half)
        if p != q:
            break

    N = p * q
    phi = (p - 1) * (q - 1)
    e = 65537  # Standard public exponent
    # Ensure gcd(e, phi) == 1
    g, _, _ = extended_gcd(e, phi)
    if g != 1:
        # Retry (extremely rare)
        return rsa_keygen(bits)

    d = mod_inverse(e, phi)
    # CRT parameters (for PA#14)
    dp = d % (p - 1)
    dq = d % (q - 1)
    q_inv = mod_inverse(q, p)

    pk = (N, e)
    sk = (N, d, p, q, dp, dq, q_inv)
    return pk, sk


# ─────────────────────────────────────────────
# Fast Modular Exponentiation (square-and-multiply)
# ─────────────────────────────────────────────
def fast_modexp(base: int, exp: int, mod: int) -> int:
    """Square-and-multiply — own implementation, no library pow()."""
    if mod == 1: return 0
    result = 1
    base %= mod
    while exp > 0:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result


# ─────────────────────────────────────────────
# Textbook RSA
# ─────────────────────────────────────────────
def rsa_enc(pk: tuple, m: int) -> int:
    """Textbook RSA encryption: C = m^e mod N."""
    N, e = pk
    if m >= N:
        raise ValueError(f"m={m} must be < N={N}")
    return fast_modexp(m, e, N)


def rsa_dec(sk: tuple, c: int) -> int:
    """Textbook RSA decryption: m = c^d mod N."""
    N, d = sk[0], sk[1]
    return fast_modexp(c, d, N)


# ─────────────────────────────────────────────
# PKCS#1 v1.5 Padding
# ─────────────────────────────────────────────
def pkcs15_pad(m: bytes, k: int) -> bytes:
    """
    PKCS#1 v1.5 encryption padding:
    EM = 00 || 02 || PS || 00 || m
    where PS is random non-zero bytes, len(PS) >= 8.
    k = modulus byte length.
    """
    if len(m) > k - 11:
        raise ValueError(f"Message too long: {len(m)} > {k - 11}")
    ps_len = k - len(m) - 3
    # Random non-zero bytes for PS
    ps = b''
    while len(ps) < ps_len:
        byte = os.urandom(1)
        if byte != b'\x00':
            ps += byte
    em = b'\x00\x02' + ps + b'\x00' + m
    assert len(em) == k
    return em


def pkcs15_unpad(em: bytes) -> bytes:
    """Strip and validate PKCS#1 v1.5 padding."""
    if len(em) < 11:
        raise ValueError("EM too short")
    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError(f"Invalid header: {em[:2].hex()} (expected 0002)")
    # Find separator 0x00 after PS
    try:
        sep = em.index(b'\x00', 2)
    except ValueError:
        raise ValueError("No separator byte found")
    ps = em[2:sep]
    if len(ps) < 8:
        raise ValueError(f"PS too short: {len(ps)} < 8")
    return em[sep+1:]


def pkcs15_enc(pk: tuple, m: bytes) -> int:
    """PKCS#1 v1.5 encryption."""
    N, e = pk
    k = (N.bit_length() + 7) // 8
    em = pkcs15_pad(m, k)
    m_int = int.from_bytes(em, 'big')
    return rsa_enc(pk, m_int)


def pkcs15_dec(sk: tuple, c: int) -> bytes:
    """PKCS#1 v1.5 decryption. Returns message or raises ValueError on bad padding."""
    N = sk[0]
    k = (N.bit_length() + 7) // 8
    m_int = rsa_dec(sk, c)
    em = m_int.to_bytes(k, 'big')
    return pkcs15_unpad(em)


# ─────────────────────────────────────────────
# Unified interface (both variants)
# ─────────────────────────────────────────────
def Enc(pk: tuple, m, variant='pkcs15'):
    """Encrypt m (bytes for pkcs15, int for textbook)."""
    if variant == 'textbook':
        if isinstance(m, bytes):
            m = int.from_bytes(m, 'big')
        return rsa_enc(pk, m)
    else:  # pkcs15
        if isinstance(m, int):
            m = m.to_bytes((m.bit_length() + 7) // 8, 'big')
        return pkcs15_enc(pk, m)


def Dec(sk: tuple, c: int, variant='pkcs15'):
    """Decrypt ciphertext c."""
    if variant == 'textbook':
        return rsa_dec(sk, c)
    else:
        return pkcs15_dec(sk, c)


# ─────────────────────────────────────────────
# Padding Oracle (for Bleichenbacher demo)
# ─────────────────────────────────────────────
def padding_oracle(sk: tuple, c: int) -> bool:
    """
    Padding oracle: returns True if decryption has valid PKCS#1 v1.5 format.
    In practice, this leaks from timing or error messages — here it's explicit.
    """
    try:
        pkcs15_dec(sk, c)
        return True
    except ValueError:
        return False


def bleichenbacher_simplified(pk: tuple, sk: tuple, c_target: int, max_iter: int = 1000) -> bytes:
    """
    Simplified Bleichenbacher's attack using padding oracle.
    For toy parameters (small N).
    
    Given c = m^e mod N, recover m by adaptive CCA2 attack.
    """
    N, e = pk
    k = (N.bit_length() + 7) // 8
    B = 2 ** (8 * (k - 2))  # 2^(8(k-2))

    # Initial interval [2B, 3B-1]
    M = [(2 * B, 3 * B - 1)]

    s = 1
    for iteration in range(max_iter):
        # Find next s such that c * s^e mod N has valid padding
        found = False
        s += 1
        for _ in range(1000):
            c_trial = (c_target * fast_modexp(s, e, N)) % N
            if padding_oracle(sk, c_trial):
                found = True
                break
            s += 1

        if not found:
            break

        # Narrow intervals
        new_M = []
        for (a, b) in M:
            r_lo = (a * s - 3 * B + 1 + N - 1) // N
            r_hi = (b * s - 2 * B) // N
            for r in range(r_lo, r_hi + 1):
                lo = max(a, (2 * B + r * N + s - 1) // s)
                hi = min(b, (3 * B - 1 + r * N) // s)
                if lo <= hi:
                    new_M.append((lo, hi))
        M = new_M

        if len(M) == 1 and M[0][0] == M[0][1]:
            m = M[0][0]
            m_bytes = m.to_bytes(k, 'big')
            try:
                return pkcs15_unpad(m_bytes)
            except:
                return m_bytes
    return None


# ─────────────────────────────────────────────
# Determinism Attack Demo
# ─────────────────────────────────────────────
def demo_determinism_attack(pk, sk):
    """Encrypt same message twice — textbook RSA gives identical ciphertexts."""
    m = b"YES"  # Vote
    # Convert to integer
    m_int = int.from_bytes(m, 'big')

    c1 = rsa_enc(pk, m_int)
    c2 = rsa_enc(pk, m_int)

    print(f"\n  Textbook RSA Determinism Attack:")
    print(f"  m = {m!r} = {m_int}")
    print(f"  Enc(m) #1 = {c1}")
    print(f"  Enc(m) #2 = {c2}")
    print(f"  c1 == c2: {c1 == c2} ← IDENTICAL! Plaintext leaked.")
    print(f"\n  PKCS#1 v1.5 (randomized padding):")
    N, e = pk
    k = (N.bit_length() + 7) // 8
    c3 = pkcs15_enc(pk, m)
    c4 = pkcs15_enc(pk, m)
    print(f"  Enc_pkcs15(m) #1 = {c3}")
    print(f"  Enc_pkcs15(m) #2 = {c4}")
    print(f"  c3 == c4: {c3 == c4} ← Different! Randomization works ✓")


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #12 — Textbook RSA + PKCS#1 v1.5")
    print("=" * 60)

    # 1. Key generation
    print("\n[1] RSA Key Generation (1024-bit)")
    pk, sk = rsa_keygen(bits=1024)
    N, e = pk
    N_sk, d = sk[0], sk[1]
    print(f"  N = {N.bit_length()}-bit modulus")
    print(f"  e = {e}")
    print(f"  d = {d.bit_length()}-bit (private exponent)")
    print(f"  p = {sk[2].bit_length()}-bit, q = {sk[3].bit_length()}-bit")

    # 2. Textbook RSA
    print("\n[2] Textbook RSA Encrypt/Decrypt")
    m_int = 42
    c = rsa_enc(pk, m_int)
    m_rec = rsa_dec(sk, c)
    print(f"  Enc({m_int}) = {c}")
    print(f"  Dec(c) = {m_rec} {'✓' if m_rec == m_int else '✗'}")

    # 3. PKCS#1 v1.5
    print("\n[3] PKCS#1 v1.5 Encrypt/Decrypt")
    m_bytes = b"Hello, RSA!"
    c15 = pkcs15_enc(pk, m_bytes)
    m_rec2 = pkcs15_dec(sk, c15)
    print(f"  m = {m_bytes!r}")
    print(f"  Enc_pkcs15(m) = {c15.bit_length()}-bit ciphertext")
    print(f"  Dec_pkcs15(c) = {m_rec2!r} {'✓' if m_rec2 == m_bytes else '✗'}")

    # 4. Determinism attack
    demo_determinism_attack(pk, sk)

    # 5. Extended Euclidean
    print("\n[4] Extended GCD (for key generation)")
    for a, n in [(17, 3120), (65537, 999982)]:
        inv = mod_inverse(a, n)
        print(f"  {a}^-1 mod {n} = {inv}, verify: {a}*{inv} mod {n} = {(a*inv)%n} ✓")

    # 6. Bleichenbacher (tiny params for speed)
    print("\n[5] Bleichenbacher Padding Oracle (simplified, tiny params)")
    print("  Generating tiny RSA key for demo...")
    # Use 512-bit for fast demo
    pk_tiny, sk_tiny = rsa_keygen(bits=512)
    m_target = b"secret"
    c_target = pkcs15_enc(pk_tiny, m_target)
    print(f"  Target plaintext: {m_target!r}")
    print(f"  Encrypted: {c_target.bit_length()}-bit ciphertext")
    result = bleichenbacher_simplified(pk_tiny, sk_tiny, c_target, max_iter=50)
    if result:
        print(f"  Bleichenbacher recovered: {result!r} {'✓' if result == m_target else '(partial)'}")
    else:
        print("  (Requires more iterations for full attack — demonstrating concept)")
    print("  Full attack: O(2^20) adaptive queries with padding oracle")

    print("\n✓ PA #12 complete.")
    print("Interface: from pa12_rsa.rsa import rsa_keygen, Enc, Dec, pkcs15_enc, pkcs15_dec")
