"""
PA #11 — Diffie-Hellman Key Exchange
CS8.401: Principles of Information Security

Implements:
1. Safe prime / generator generation (using PA#13)
2. DH protocol: both parties (Alice, Bob)
3. MITM attack demo
4. CDH hardness demo
5. Interface: dh_alice_step1(), dh_bob_step1(), dh_alice_step2(), dh_bob_step2()
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa13_miller_rabin'))
from miller_rabin import mod_exp, gen_safe_prime, is_prime


# ─────────────────────────────────────────────
# DH Group Parameters
# ─────────────────────────────────────────────
class DHParams:
    """
    Safe prime group: p = 2q + 1, generator g of order q.
    """
    def __init__(self, bits=64):
        print(f"  Generating {bits}-bit safe prime for DH...")
        self.p, self.q = gen_safe_prime(bits)
        self.g = self._find_generator()
        print(f"  p = {self.p}  ({self.p.bit_length()}-bit)")
        print(f"  q = {self.q}")
        print(f"  g = {self.g}")

    def _find_generator(self) -> int:
        """Find generator g of prime-order-q subgroup of Zp*."""
        p, q = self.p, self.q
        while True:
            h = int.from_bytes(os.urandom(8), 'big') % (p - 2) + 2
            g = mod_exp(h, 2, p)
            if g != 1 and mod_exp(g, q, p) == 1:
                return g


# ─────────────────────────────────────────────
# DH Protocol
# ─────────────────────────────────────────────
def dh_alice_step1(params: DHParams) -> tuple:
    """
    Alice: sample a <- Zq, compute A = g^a mod p.
    Returns (a, A): private exponent and public value.
    """
    a = int.from_bytes(os.urandom(8), 'big') % params.q
    A = mod_exp(params.g, a, params.p)
    return a, A


def dh_bob_step1(params: DHParams) -> tuple:
    """
    Bob: sample b <- Zq, compute B = g^b mod p.
    Returns (b, B): private exponent and public value.
    """
    b = int.from_bytes(os.urandom(8), 'big') % params.q
    B = mod_exp(params.g, b, params.p)
    return b, B


def dh_alice_step2(params: DHParams, a: int, B: int) -> int:
    """
    Alice: compute K = B^a = g^(ab) mod p.
    """
    return mod_exp(B, a, params.p)


def dh_bob_step2(params: DHParams, b: int, A: int) -> int:
    """
    Bob: compute K = A^b = g^(ab) mod p.
    """
    return mod_exp(A, b, params.p)


# ─────────────────────────────────────────────
# MITM Attack
# ─────────────────────────────────────────────
class MITM_Attack:
    """
    Eve intercepts DH exchange, replaces values with her own.
    Establishes separate shared secrets with Alice and Bob.
    Reads all traffic by decrypting with one key and re-encrypting with the other.
    """
    def __init__(self, params: DHParams):
        self.params = params
        self.e = int.from_bytes(os.urandom(8), 'big') % params.q
        self.E = mod_exp(params.g, self.e, params.p)
        self.K_alice = None
        self.K_bob = None

    def intercept_from_alice(self, A: int) -> int:
        """
        Eve intercepts A from Alice.
        Sends E (her own value) to Bob instead.
        Computes K_alice = A^e.
        """
        self.K_alice = mod_exp(A, self.e, self.params.p)
        return self.E  # Send Eve's value to Bob

    def intercept_from_bob(self, B: int) -> int:
        """
        Eve intercepts B from Bob.
        Sends E (her own value) to Alice instead.
        Computes K_bob = B^e.
        """
        self.K_bob = mod_exp(B, self.e, self.params.p)
        return self.E  # Send Eve's value to Alice


# ─────────────────────────────────────────────
# CDH Hardness Demo
# ─────────────────────────────────────────────
def cdh_hardness_demo(params: DHParams):
    """
    For small group (q ≈ 2^20), demonstrate brute-force DH requires
    computing g^a from g and g^a — impossible without knowing a.
    """
    print("\n  CDH Hardness Demo:")
    # Use small parameters for demonstration
    # (our default is 64-bit, which is already brute-forceable in finite time
    # but shows the concept)
    a = int.from_bytes(os.urandom(4), 'big') % min(params.q, 2**20)
    b = int.from_bytes(os.urandom(4), 'big') % min(params.q, 2**20)
    A = mod_exp(params.g, a, params.p)
    B = mod_exp(params.g, b, params.p)
    K = mod_exp(params.g, (a * b) % params.q, params.p)

    print(f"  Alice's public: A = g^a = {A}")
    print(f"  Bob's   public: B = g^b = {B}")
    print(f"  Shared secret K = g^(ab) = {K}")
    print(f"  Eve sees A, B but NOT a, b.")

    # Brute force: Eve tries to find a by DL
    if min(params.q, 2**20) < 10000:
        start = time.time()
        found_a = None
        for guess in range(min(params.q, 2**20)):
            if mod_exp(params.g, guess, params.p) == A:
                found_a = guess
                break
        elapsed = time.time() - start
        if found_a is not None:
            K_eve = mod_exp(B, found_a, params.p)
            print(f"  Eve brute-forced a={found_a} in {elapsed:.3f}s (small group)")
            print(f"  Eve computes K = {K_eve} {'==' if K_eve == K else '!='} K ✓")
        print(f"  For real 2048-bit groups: brute force infeasible (>10^600 operations)")
    else:
        print(f"  Group order q ≈ 2^{params.q.bit_length()}: brute force infeasible")
        print(f"  Best known algorithm (GNFS): sub-exponential but still huge")


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #11 — Diffie-Hellman Key Exchange")
    print("=" * 60)

    print("\n[1] Group Parameter Generation")
    params = DHParams(bits=64)

    # 2. Standard DH exchange
    print("\n[2] DH Key Exchange")
    a, A = dh_alice_step1(params)
    b, B = dh_bob_step1(params)
    print(f"  Alice: a (secret) = {a}, A = g^a = {A}")
    print(f"  Bob:   b (secret) = {b}, B = g^b = {B}")

    K_alice = dh_alice_step2(params, a, B)
    K_bob   = dh_bob_step2(params, b, A)

    print(f"\n  Alice computes K = B^a = {K_alice}")
    print(f"  Bob   computes K = A^b = {K_bob}")
    assert K_alice == K_bob, "Key exchange failed!"
    print(f"  K_alice == K_bob: True ✓")

    # 3. MITM attack
    print("\n[3] MITM Attack Demo")
    eve = MITM_Attack(params)
    a2, A2 = dh_alice_step1(params)
    b2, B2 = dh_bob_step1(params)

    # Eve intercepts
    A_to_bob = eve.intercept_from_alice(A2)    # Eve replaces A with E
    B_to_alice = eve.intercept_from_bob(B2)    # Eve replaces B with E

    # Alice thinks she's talking to Bob (but gets E from Eve)
    K_alice_mitm = dh_alice_step2(params, a2, B_to_alice)
    # Bob thinks he's talking to Alice (but gets E from Eve)
    K_bob_mitm = dh_bob_step2(params, b2, A_to_bob)

    print(f"  Without MITM: Alice and Bob share same key ✓")
    print(f"  With MITM Eve:")
    print(f"    Eve's K_alice (shared with Alice) = {eve.K_alice}")
    print(f"    Eve's K_bob   (shared with Bob)   = {eve.K_bob}")
    print(f"    Alice's view of shared key: {K_alice_mitm}")
    print(f"    Bob's   view of shared key: {K_bob_mitm}")
    print(f"    Eve holds BOTH keys → reads all traffic!")
    print(f"    Fix: Authenticate with digital signatures (PA#15)")

    # 4. CDH hardness
    cdh_hardness_demo(params)

    print("\n✓ PA #11 complete.")
    print("Interface: from pa11_dh.dh import DHParams, dh_alice_step1, dh_bob_step2, ...")
