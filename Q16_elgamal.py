"""
PA #16 — ElGamal Public-Key Cryptosystem
CS8.401: Principles of Information Security

Implements:
1. ElGamal key generation using PA#11 group parameters
2. ElGamal encryption: Enc(pk, m) = (g^r, m * h^r) mod p
3. ElGamal decryption: Dec(sk, c1, c2) = c2 / c1^x mod p
4. Malleability attack: (c1, 2*c2 mod p) decrypts to 2m — CCA insecurity demo
5. IND-CPA game simulation
6. DDH hardness demonstration

Dependencies: PA#11 (DH group), PA#13 (Miller-Rabin for prime generation)
No external cryptographic libraries used.
"""

import os
import sys
import random
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa13_miller_rabin'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa11_dh'))

from Q13_miller_rabin import mod_exp, gen_prime, gen_safe_prime


# ---------------------------------------------------------------------------
# Group Parameters (reuse PA#11 approach)
# ---------------------------------------------------------------------------

class ElGamalParams:
    """
    Prime-order subgroup of Z*_p for ElGamal.
    p = safe prime (2q+1), g = generator of subgroup of order q.
    """
    def __init__(self, bits: int = 256):
        self.p, self.q = gen_safe_prime(bits)
        # Find generator of the subgroup of order q
        # Elements of the form a^2 mod p (where a != ±1) have order q in Z*_p
        while True:
            a = random.randint(2, self.p - 2)
            g_cand = mod_exp(a, 2, self.p)
            if g_cand != 1 and g_cand != self.p - 1:
                # Verify order is q: g^q mod p should be 1
                if mod_exp(g_cand, self.q, self.p) == 1:
                    self.g = g_cand
                    break

    def random_element(self) -> int:
        """Sample a random element of the subgroup."""
        exp = random.randint(1, self.q - 1)
        return mod_exp(self.g, exp, self.p)

    def __repr__(self):
        return (f"ElGamalParams(bits≈{self.p.bit_length()}, "
                f"p={self.p}, q={self.q}, g={self.g})")


# ---------------------------------------------------------------------------
# ElGamal Key Generation
# ---------------------------------------------------------------------------

def elgamal_keygen(params: ElGamalParams = None, bits: int = 256):
    """
    ElGamal key generation.
    Returns (pk, sk) where:
      pk = (p, g, q, h)   with h = g^x mod p
      sk = x              (private exponent)

    Uses PA#11-style safe prime group.
    """
    if params is None:
        params = ElGamalParams(bits)
    p, g, q = params.p, params.g, params.q
    # Private key: random x in [1, q-1]
    x = random.randint(1, q - 1)
    # Public key component: h = g^x mod p
    h = mod_exp(g, x, p)
    pk = (p, g, q, h)
    sk = x
    return pk, sk


# ---------------------------------------------------------------------------
# ElGamal Encryption / Decryption
# ---------------------------------------------------------------------------

def ElGamal_Enc(pk, m: int) -> tuple:
    """
    ElGamal Encryption.
    Input: pk = (p, g, q, h), m = plaintext as group element (int in [1, p-1])
    Output: (c1, c2) where:
      c1 = g^r mod p
      c2 = m * h^r mod p
    r is a fresh random element from Z_q each call (CPA randomness).

    Security: Under DDH, (g^r, h^r) is indistinguishable from (g^r, random).
    """
    p, g, q, h = pk
    if not (1 <= m < p):
        raise ValueError(f"Message {m} must be in [1, p-1]")
    # Fresh random r for each encryption (critical for CPA security)
    r = random.randint(1, q - 1)
    c1 = mod_exp(g, r, p)
    hr = mod_exp(h, r, p)
    c2 = (m * hr) % p
    return c1, c2


def ElGamal_Dec(pk, sk: int, c1: int, c2: int) -> int:
    """
    ElGamal Decryption.
    Input: pk = (p, g, q, h), sk = x, ciphertext (c1, c2)
    Output: m = c2 / c1^x mod p = c2 * (c1^x)^{-1} mod p

    Correctness:
      c2 / c1^x = m * h^r / (g^r)^x = m * g^{xr} / g^{xr} = m
    """
    p, g, q, h = pk
    # c1^x mod p
    c1_x = mod_exp(c1, sk, p)
    # Modular inverse of c1^x
    c1_x_inv = pow(c1_x, -1, p)   # Python 3.8+ built-in modular inverse (integer arithmetic only)
    m = (c2 * c1_x_inv) % p
    return m


# ---------------------------------------------------------------------------
# Malleability Attack (CCA Insecurity Demo)
# ---------------------------------------------------------------------------

def malleability_attack_multiply(pk, c1: int, c2: int, factor: int) -> tuple:
    """
    ElGamal Malleability Attack.

    Given ciphertext (c1, c2) encrypting unknown message m:
      c2' = factor * c2 mod p
    The modified ciphertext (c1, c2') decrypts to factor * m mod p.

    This works because:
      Dec(c1, factor * c2) = factor * c2 / c1^x = factor * m * h^r / h^r = factor * m

    This breaks CCA security: adversary submits modified ciphertext to decryption
    oracle and learns factor*m, from which m = factor*m / factor.

    No knowledge of sk or m is required.
    """
    p, g, q, h = pk
    c2_modified = (factor * c2) % p
    return c1, c2_modified


def demo_malleability(params: ElGamalParams = None, bits: int = 128):
    """Demonstrate the ElGamal malleability attack."""
    print("\n=== ElGamal Malleability Attack Demo ===")
    if params is None:
        params = ElGamalParams(bits)
    pk, sk = elgamal_keygen(params)
    p, g, q, h = pk

    # Original message: a random group element
    m = params.random_element()
    print(f"  Original message m = {m}")

    # Encrypt
    c1, c2 = ElGamal_Enc(pk, m)
    print(f"  Ciphertext (c1, c2) = ({c1}, {c2})")

    # Attack: multiply ciphertext by 2
    factor = 2
    c1_mod, c2_mod = malleability_attack_multiply(pk, c1, c2, factor)
    print(f"  Modified (c1, {factor}*c2 mod p) = ({c1_mod}, {c2_mod})")

    # Decrypt modified ciphertext
    m_decrypted = ElGamal_Dec(pk, sk, c1_mod, c2_mod)
    expected = (factor * m) % p
    print(f"  Decrypted modified: {m_decrypted}")
    print(f"  Expected {factor}*m mod p = {expected}")
    print(f"  Match: {m_decrypted == expected}")
    print(f"  >>> Malleability confirmed: Dec(c1, 2*c2) = 2*m without knowing sk or m")
    return m_decrypted == expected


# ---------------------------------------------------------------------------
# IND-CPA Game
# ---------------------------------------------------------------------------

class IND_CPA_Game_ElGamal:
    """
    IND-CPA (indistinguishability under chosen-plaintext attack) game for ElGamal.

    The challenger holds (pk, sk).
    Phase 1: Adversary queries Enc(m) for any messages.
    Challenge: Adversary submits (m0, m1); challenger picks random b, returns C* = Enc(m_b).
    Phase 2: Adversary may continue querying Enc (but NOT Dec).
    Guess: Adversary guesses b' = 0 or 1.
    Adversary wins if b' == b. Advantage = |Pr[win] - 1/2|.

    A secure scheme gives advantage ≈ 0.
    """

    def __init__(self, params: ElGamalParams = None, bits: int = 128):
        if params is None:
            params = ElGamalParams(bits)
        self.params = params
        self.pk, self.sk = elgamal_keygen(params)
        self._b = None
        self._challenge_sent = False

    def enc_oracle(self, m: int) -> tuple:
        """Encryption oracle available in both phases."""
        return ElGamal_Enc(self.pk, m)

    def challenge(self, m0: int, m1: int) -> tuple:
        """Challenger picks random b and returns encryption of m_b."""
        self._b = random.randint(0, 1)
        m_b = m0 if self._b == 0 else m1
        self._challenge_ciphertext = ElGamal_Enc(self.pk, m_b)
        self._challenge_sent = True
        return self._challenge_ciphertext

    def guess(self, b_prime: int) -> bool:
        """Adversary submits guess. Returns True if adversary wins."""
        assert self._challenge_sent, "Challenge must be sent before guess."
        return b_prime == self._b

    def run_dummy_adversary(self, num_trials: int = 100):
        """
        Dummy adversary: makes random guesses.
        Expected advantage: ≈ 0 (wins ~50% of the time by chance).
        """
        print(f"\n=== IND-CPA Game: Dummy Adversary ({num_trials} trials) ===")
        wins = 0
        p = self.params.p
        for _ in range(num_trials):
            # Adversary picks two messages
            m0 = self.params.random_element()
            m1 = self.params.random_element()
            while m1 == m0:
                m1 = self.params.random_element()
            # Get challenge ciphertext
            c_star = self.challenge(m0, m1)
            # Dummy adversary: random guess
            b_guess = random.randint(0, 1)
            if self.guess(b_guess):
                wins += 1
            # Reset for next round
            self._challenge_sent = False

        advantage = abs(wins / num_trials - 0.5)
        print(f"  Wins: {wins}/{num_trials}")
        print(f"  Advantage: {advantage:.4f} (expected ≈ 0)")
        return advantage


# ---------------------------------------------------------------------------
# DDH Hardness Demo
# ---------------------------------------------------------------------------

def ddh_hardness_demo(params: ElGamalParams = None, bits: int = 64):
    """
    Demonstrate Decisional Diffie-Hellman (DDH) hardness.

    DDH: Given (g, g^a, g^b, g^c) in group G, decide if c == ab mod q.

    For a small group (q ≈ 2^20), show that a brute-force distinguisher
    must enumerate O(q) values, while for a proper-sized group it's infeasible.

    In a large group: DDH is hard → ElGamal is CPA-secure.
    In a tiny group: DDH is easy → adversary wins IND-CPA trivially.
    """
    print(f"\n=== DDH Hardness Demo (tiny {bits}-bit group) ===")
    if params is None:
        params = ElGamalParams(bits)
    p, g, q = params.p, params.g, params.q

    # Challenger gives (g^a, g^b, g^c); adversary must decide if g^c == g^(ab)
    a = random.randint(1, q - 1)
    b = random.randint(1, q - 1)
    g_a = mod_exp(g, a, p)
    g_b = mod_exp(g, b, p)
    g_ab = mod_exp(g, (a * b) % q, p)

    # Coin flip: with prob 1/2, give real tuple; with prob 1/2, give random
    real = random.randint(0, 1)
    if real:
        g_c = g_ab
    else:
        c_random = random.randint(1, q - 1)
        g_c = mod_exp(g, c_random, p)

    print(f"  g^a = {g_a}, g^b = {g_b}, g^c = {g_c}")
    print(f"  Is (g^a, g^b, g^c) a DDH tuple? (actual: {bool(real)})")

    # Brute-force distinguisher: compute DL of g^a by exhaustive search
    t0 = time.time()
    found_a = None
    for i in range(1, min(q, 2**20)):
        if mod_exp(g, i, p) == g_a:
            found_a = i
            break
    elapsed = time.time() - t0

    if found_a is not None:
        g_check = mod_exp(g_b, found_a, p)
        adversary_answer = (g_check == g_c)
        print(f"  Brute-force found a={found_a} in {elapsed:.4f}s")
        print(f"  Adversary correctly identifies DDH tuple: {adversary_answer == real}")
        print(f"  >>> In tiny group: DDH is easy (brute-forceable) → ElGamal insecure!")
    else:
        print(f"  Brute-force could not find a in feasible time → DDH is hard in this group")

    print(f"  For large group (256+ bits): same computation takes ~2^128 ops — infeasible")


# ---------------------------------------------------------------------------
# Public Interface for PA#17 and PA#18
# ---------------------------------------------------------------------------

def Enc(pk, m: int) -> tuple:
    """Public interface: Enc(pk, m) -> (c1, c2)"""
    return ElGamal_Enc(pk, m)


def Dec(pk, sk: int, c1: int, c2: int) -> int:
    """Public interface: Dec(pk, sk, c1, c2) -> m"""
    return ElGamal_Dec(pk, sk, c1, c2)


# ---------------------------------------------------------------------------
# Self-test / demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 65)
    print("PA #16 — ElGamal Public-Key Cryptosystem")
    print("=" * 65)

    print("\n[1] Generating ElGamal parameters and key pair (128-bit)...")
    t0 = time.time()
    params = ElGamalParams(bits=128)
    pk, sk = elgamal_keygen(params)
    p, g, q, h = pk
    print(f"    p = {p}")
    print(f"    g = {g} (generator, order q)")
    print(f"    q = {q}")
    print(f"    h = g^x = {h}")
    print(f"    sk = x = {sk}")
    print(f"    Key generation time: {time.time()-t0:.3f}s")

    print("\n[2] Encrypt and Decrypt a message...")
    m_original = params.random_element()
    c1, c2 = ElGamal_Enc(pk, m_original)
    m_decrypted = ElGamal_Dec(pk, sk, c1, c2)
    print(f"    m         = {m_original}")
    print(f"    (c1, c2)  = ({c1}, {c2})")
    print(f"    decrypted = {m_decrypted}")
    print(f"    Correct:  {m_original == m_decrypted}")
    assert m_original == m_decrypted, "Decryption failed!"

    print("\n[3] Ciphertext is randomised (different each encryption)...")
    c1b, c2b = ElGamal_Enc(pk, m_original)
    print(f"    First  encryption:  c1={c1}, c2={c2}")
    print(f"    Second encryption:  c1={c1b}, c2={c2b}")
    print(f"    Ciphertexts differ: {(c1, c2) != (c1b, c2b)}")
    assert (c1, c2) != (c1b, c2b), "Same ciphertext produced! Randomisation broken."

    print("\n[4] Multiple messages encrypt/decrypt correctly...")
    for _ in range(10):
        m = params.random_element()
        c = ElGamal_Enc(pk, m)
        m2 = ElGamal_Dec(pk, sk, *c)
        assert m == m2, f"Decryption mismatch for m={m}"
    print("    All 10 random messages encrypt/decrypt correctly.")

    print("\n[5] Malleability Attack (CCA insecurity)...")
    result = demo_malleability(params)
    assert result, "Malleability attack failed unexpectedly"

    print("\n[6] IND-CPA Game (dummy adversary)...")
    game = IND_CPA_Game_ElGamal(params)
    advantage = game.run_dummy_adversary(num_trials=200)
    print(f"    Adversary advantage: {advantage:.4f} (should be ≈ 0)")
    assert advantage < 0.1, f"Advantage {advantage} too large — CPA may be broken!"

    print("\n[7] DDH Hardness Demo...")
    ddh_hardness_demo(bits=64)

    print("\n[8] Testing public interface (Enc/Dec)...")
    m_test = params.random_element()
    c1t, c2t = Enc(pk, m_test)
    m_test_dec = Dec(pk, sk, c1t, c2t)
    assert m_test == m_test_dec
    print(f"    Enc/Dec interface works: {m_test == m_test_dec}")

    print("\n" + "=" * 65)
    print("All PA#16 tests passed.")
    print("=" * 65)
