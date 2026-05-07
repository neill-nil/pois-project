"""
PA #15 — Digital Signatures
CS8.401: Principles of Information Security

Implements:
1. RSA Hash-then-Sign signature scheme using PA#12 RSA + PA#8 DLP Hash
2. Sign(sk, m) = H(m)^d mod N   (hash-then-sign, not raw RSA)
3. Verify(vk, m, sigma) = (sigma^e mod N == H(m))
4. EUF-CMA security game simulation
5. Multiplicative forgery attack on raw (non-hashed) RSA signatures
6. Optional ElGamal/Schnorr signatures (DLP-based)

Dependencies: PA#12 (RSA), PA#13 (Miller-Rabin), PA#8 (DLP Hash)
No external cryptographic libraries used.
"""

import os
import sys
import time
import random

# ---------------------------------------------------------------------------
# Dependency imports — must use own implementations
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa13_miller_rabin'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa12_rsa'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa8_dlp_hash'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa11_dh'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa7_merkle'))

from miller_rabin import gen_prime, miller_rabin, mod_exp
from rsa import (rsa_keygen, rsa_enc, rsa_dec, extended_gcd, mod_inverse,
                 fast_modexp)
from dlp_hash import DLP_Hash, DLPHashParams


# ---------------------------------------------------------------------------
# Helper: hash a message to an integer in [0, N) using PA#8 DLP Hash
# ---------------------------------------------------------------------------

_hash_instance = None

def _get_hasher():
    global _hash_instance
    if _hash_instance is None:
        _hash_instance = DLP_Hash()
    return _hash_instance


def hash_message_to_int(message: bytes, modulus: int) -> int:
    """
    Hash an arbitrary message to an integer in [1, modulus-1].
    Uses PA#8 DLP Hash, then interprets the digest bytes as a big-endian integer
    and reduces modulo (modulus - 1) + 1 to avoid zero.
    """
    hasher = _get_hasher()
    if isinstance(message, str):
        message = message.encode()
    digest_bytes = hasher.hash(message)          # bytes from DLP Hash
    digest_int = int.from_bytes(digest_bytes, 'big')
    # Reduce into [1, modulus-1]
    h = (digest_int % (modulus - 1)) + 1
    return h


# ---------------------------------------------------------------------------
# RSA Key Generation (wraps PA#12)
# ---------------------------------------------------------------------------

def sig_keygen(bits: int = 512):
    """
    Generate an RSA key pair for signing.
    Returns (sk, vk) where:
      sk = (N, d, p, q)
      vk = (N, e)
    Uses PA#12 rsa_keygen under the hood.
    """
    pk, sk_full = rsa_keygen(bits)
    N, e = pk
    N2, d, p, q, dp, dq, q_inv = sk_full
    sk = (N, d, p, q)
    vk = (N, e)
    return sk, vk


# ---------------------------------------------------------------------------
# RSA Hash-then-Sign
# ---------------------------------------------------------------------------

def sign(sk, message: bytes) -> int:
    """
    Sign a message using RSA hash-then-sign.
    sigma = H(m)^d mod N

    Steps:
      1. Compute h = H(m) as integer in [1, N-1]  (PA#8 DLP Hash)
      2. Compute sigma = h^d mod N  (fast_modexp from PA#12)

    This is NOT raw RSA signing (which would be sigma = m^d mod N).
    Hashing prevents the multiplicative forgery attack on the final scheme.
    """
    N, d, p, q = sk
    if isinstance(message, str):
        message = message.encode()
    h = hash_message_to_int(message, N)
    sigma = fast_modexp(h, d, N)
    return sigma


def verify(vk, message: bytes, sigma: int) -> bool:
    """
    Verify an RSA signature.
    Check: sigma^e mod N == H(m)

    Steps:
      1. Compute h = H(m) as integer
      2. Compute recovered = sigma^e mod N
      3. Return recovered == h
    """
    N, e = vk
    if isinstance(message, str):
        message = message.encode()
    h = hash_message_to_int(message, N)
    recovered = fast_modexp(sigma, e, N)
    return recovered == h


# ---------------------------------------------------------------------------
# EUF-CMA Security Game
# ---------------------------------------------------------------------------

class EUF_CMA_Game:
    """
    Existential Unforgeability under Chosen Message Attack game.

    The challenger holds a signing key sk.
    The adversary may query Sign(m) for any messages of their choice.
    The adversary then attempts to produce (m*, sigma*) where:
      - m* was NOT previously queried
      - Verify(vk, m*, sigma*) == True

    A secure scheme should yield 0 successful forgeries.
    """

    def __init__(self, bits: int = 512):
        self.sk, self.vk = sig_keygen(bits)
        self.queried_messages = set()
        self.query_count = 0
        self.forgery_attempts = 0
        self.forgery_successes = 0

    def sign_oracle(self, message: bytes) -> int:
        """Signing oracle: adversary can call this on any message."""
        if isinstance(message, str):
            message = message.encode()
        self.queried_messages.add(message)
        self.query_count += 1
        return sign(self.sk, message)

    def submit_forgery(self, message: bytes, sigma: int) -> bool:
        """
        Adversary submits a forgery attempt.
        Returns True if forgery succeeds (adversary wins), False otherwise.
        """
        if isinstance(message, str):
            message = message.encode()
        self.forgery_attempts += 1
        # Forgery is only valid if message was NOT previously queried
        if message in self.queried_messages:
            print(f"  [GAME] Message was already queried — not a forgery.")
            return False
        result = verify(self.vk, message, sigma)
        if result:
            self.forgery_successes += 1
            print(f"  [GAME] FORGERY SUCCEEDED on message: {message[:32]}...")
        else:
            print(f"  [GAME] Forgery rejected.")
        return result

    def run_naive_adversary(self, num_queries: int = 50):
        """
        Naive adversary: queries 50 messages, then tries random guesses.
        Expected result: 0 successes.
        """
        print(f"\n=== EUF-CMA Game: Naive Adversary ({num_queries} queries) ===")
        # Phase 1: query signing oracle
        signed_pairs = []
        for i in range(num_queries):
            m = f"message_{i}_{os.urandom(4).hex()}".encode()
            sig = self.sign_oracle(m)
            signed_pairs.append((m, sig))
        print(f"  Adversary collected {num_queries} (message, signature) pairs.")

        # Phase 2: attempt forgeries on new messages
        print(f"  Attempting 20 forgeries on unseen messages...")
        for i in range(20):
            # Random new message
            m_new = f"forgery_attempt_{i}_{os.urandom(8).hex()}".encode()
            # Random sigma guess
            N, e = self.vk
            sigma_guess = random.randint(1, N - 1)
            self.submit_forgery(m_new, sigma_guess)

        print(f"\n  Result: {self.forgery_successes}/{self.forgery_attempts} forgeries succeeded.")
        print(f"  Expected: 0 successes (negligible probability).")
        return self.forgery_successes


# ---------------------------------------------------------------------------
# Multiplicative Forgery on Raw RSA (without hashing)
# ---------------------------------------------------------------------------

def raw_rsa_sign(sk, message_int: int) -> int:
    """
    INSECURE: Sign an integer directly without hashing.
    sigma = m^d mod N
    This is vulnerable to multiplicative forgery.
    """
    N, d, p, q = sk
    return fast_modexp(message_int, d, N)


def raw_rsa_verify(vk, message_int: int, sigma: int) -> bool:
    """Verify raw RSA signature: sigma^e mod N == m."""
    N, e = vk
    return fast_modexp(sigma, e, N) == message_int


def multiplicative_forgery_attack(vk, m1: int, sigma1: int, m2: int, sigma2: int) -> tuple:
    """
    Multiplicative Homomorphism Attack on raw (unhashed) RSA signatures.

    Given:
      sigma1 = m1^d mod N   (valid signature on m1)
      sigma2 = m2^d mod N   (valid signature on m2)

    Forge:
      sigma_forged = sigma1 * sigma2 mod N
      This is a valid signature on m1 * m2 mod N, because:
      (sigma1 * sigma2)^e = m1^(d*e) * m2^(d*e) = m1 * m2 mod N

    The attacker produces a valid (m3, sigma3) where m3 = m1*m2 mod N,
    WITHOUT ever querying the signing oracle on m3.
    """
    N, e = vk
    m3 = (m1 * m2) % N
    sigma_forged = (sigma1 * sigma2) % N
    return m3, sigma_forged


def demo_multiplicative_forgery(bits: int = 256):
    """
    Demonstrate the multiplicative forgery attack on raw RSA.
    Then show that hash-then-sign prevents this attack.
    """
    print("\n=== Multiplicative Forgery Attack on Raw RSA ===")
    sk, vk = sig_keygen(bits)
    N, e = vk

    # Choose two messages as integers < N
    m1 = random.randint(2, N // 4)
    m2 = random.randint(2, N // 4)
    m3_target = (m1 * m2) % N

    # Get valid signatures on m1 and m2 from signing oracle
    sigma1 = raw_rsa_sign(sk, m1)
    sigma2 = raw_rsa_sign(sk, m2)
    print(f"  m1 = {m1}")
    print(f"  m2 = {m2}")
    print(f"  m3 = m1*m2 mod N = {m3_target}")
    print(f"  sigma1 (sign m1) = {sigma1}")
    print(f"  sigma2 (sign m2) = {sigma2}")

    # Forge signature on m3 WITHOUT querying the oracle on m3
    m3_forged, sigma_forged = multiplicative_forgery_attack(vk, m1, sigma1, m2, sigma2)
    valid = raw_rsa_verify(vk, m3_forged, sigma_forged)
    print(f"\n  Forged signature on m3 = {sigma_forged}")
    print(f"  raw_rsa_verify(m3, sigma_forged) = {valid}")
    print(f"  >>> FORGERY {'SUCCEEDED' if valid else 'FAILED'} on message not queried to oracle!")

    print("\n--- Now attempting same attack on Hash-then-Sign ---")
    # With hash-then-sign, sigma = H(m)^d mod N
    # sigma1_hashed * sigma2_hashed = H(m1)^d * H(m2)^d = (H(m1)*H(m2))^d mod N
    # This is a signature on the integer H(m1)*H(m2) mod N, which is NOT H(m1*m2 mod N)
    # So it cannot be used to forge a signature on any meaningful message.
    m1_bytes = m1.to_bytes((m1.bit_length() + 7) // 8, 'big')
    m2_bytes = m2.to_bytes((m2.bit_length() + 7) // 8, 'big')
    sigma1_hashed = sign(sk, m1_bytes)
    sigma2_hashed = sign(sk, m2_bytes)
    # Attempt to forge for m3
    m3_bytes = m3_target.to_bytes((m3_target.bit_length() + 7) // 8, 'big')
    sigma_forged_h = (sigma1_hashed * sigma2_hashed) % N
    valid_hashed = verify(vk, m3_bytes, sigma_forged_h)
    print(f"  Attempted forgery on m3 (hash-then-sign): valid = {valid_hashed}")
    print(f"  >>> Hash-then-sign forgery {'SUCCEEDED (unexpected!)' if valid_hashed else 'FAILED (expected — hash breaks multiplicativity)'}")
    return valid, valid_hashed


# ---------------------------------------------------------------------------
# ElGamal / Schnorr Signatures (DLP-based alternative)
# ---------------------------------------------------------------------------

class SchnorrSignature:
    """
    Schnorr Signature Scheme over a prime-order group.
    DLP-based alternative to RSA signatures.

    Setup: Group (p, q, g) where g has prime order q in Z*_p.
    Key generation: sk = x <- Z_q, vk = y = g^x mod p
    Sign(sk, m):
      1. r <- Z_q  (random nonce)
      2. R = g^r mod p
      3. e = H(R || m)   (hash)
      4. s = (r - x*e) mod q
      Output: (e, s)
    Verify(vk, m, (e, s)):
      1. R' = g^s * y^e mod p
      2. Check: e == H(R' || m)
    """

    def __init__(self, bits: int = 256):
        """Initialize with a safe prime group from PA#13."""
        from miller_rabin import gen_safe_prime
        # Generate safe prime p = 2q + 1
        p_bits = bits
        self.p, self.q = gen_safe_prime(p_bits)
        # Find generator of the prime-order subgroup of order q
        # In a safe-prime group, elements of order q are squares mod p
        while True:
            candidate = random.randint(2, self.p - 2)
            g_cand = mod_exp(candidate, 2, self.p)
            if g_cand != 1:
                self.g = g_cand
                break
        self._hasher = DLP_Hash()

    def keygen(self):
        """Generate Schnorr key pair. Returns (sk=x, vk=y)."""
        x = random.randint(1, self.q - 1)
        y = mod_exp(self.g, x, self.p)
        return x, y

    def _hash_challenge(self, R: int, message: bytes) -> int:
        """Compute challenge e = H(R || message) as integer mod q."""
        R_bytes = R.to_bytes((R.bit_length() + 7) // 8, 'big')
        data = R_bytes + message
        digest = self._hasher.hash(data)
        return int.from_bytes(digest, 'big') % self.q

    def sign(self, sk_x: int, message: bytes) -> tuple:
        """Schnorr sign. Returns (e, s)."""
        if isinstance(message, str):
            message = message.encode()
        r = random.randint(1, self.q - 1)
        R = mod_exp(self.g, r, self.p)
        e = self._hash_challenge(R, message)
        s = (r - sk_x * e) % self.q
        return (e, s)

    def verify(self, vk_y: int, message: bytes, signature: tuple) -> bool:
        """Schnorr verify. Returns True if valid."""
        if isinstance(message, str):
            message = message.encode()
        e, s = signature
        # R' = g^s * y^e mod p
        R_prime = (mod_exp(self.g, s, self.p) * mod_exp(vk_y, e, self.p)) % self.p
        e_check = self._hash_challenge(R_prime, message)
        return e_check == e


# ---------------------------------------------------------------------------
# Interface for PA#17
# ---------------------------------------------------------------------------

def Sign(sk, message) -> int:
    """
    Public interface: Sign(sk, message) -> sigma
    Uses RSA hash-then-sign (PA#8 hash + PA#12 RSA).
    sk = (N, d, p, q)
    """
    if isinstance(message, str):
        message = message.encode()
    return sign(sk, message)


def Verify(vk, message, sigma: int) -> bool:
    """
    Public interface: Verify(vk, message, sigma) -> bool
    vk = (N, e)
    """
    if isinstance(message, str):
        message = message.encode()
    return verify(vk, message, sigma)


# ---------------------------------------------------------------------------
# Self-test / demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 65)
    print("PA #15 — Digital Signatures")
    print("=" * 65)

    print("\n[1] Generating RSA key pair (512-bit)...")
    t0 = time.time()
    sk, vk = sig_keygen(bits=512)
    N, d, p, q = sk
    N2, e = vk
    print(f"    N = {N}")
    print(f"    e = {e}")
    print(f"    Key generation time: {time.time()-t0:.3f}s")

    print("\n[2] Sign and Verify a message...")
    message = b"The quick brown fox jumps over the lazy dog"
    sigma = Sign(sk, message)
    valid = Verify(vk, message, sigma)
    print(f"    Message:   {message.decode()}")
    print(f"    Signature: {sigma}")
    print(f"    Valid:     {valid}")
    assert valid, "Signature verification failed!"

    print("\n[3] Tampered message fails verification...")
    tampered = b"The quick brown fox jumps over the lazy CAT"
    valid_tampered = Verify(vk, tampered, sigma)
    print(f"    Tampered:  {tampered.decode()}")
    print(f"    Valid:     {valid_tampered}")
    assert not valid_tampered, "Tampered message should not verify!"

    print("\n[4] Wrong signature fails verification...")
    wrong_sigma = sigma ^ (1 << 10)
    valid_wrong = Verify(vk, message, wrong_sigma)
    print(f"    Valid with wrong sig: {valid_wrong}")
    assert not valid_wrong

    print("\n[5] Multiple messages sign and verify...")
    messages = [
        b"Vote: YES",
        b"Vote: NO",
        b"Transaction: Alice -> Bob: $100",
        b"Certificate: Alice's public key is valid until 2025",
        b"" ,  # empty message
    ]
    for m in messages:
        s = Sign(sk, m)
        v = Verify(vk, m, s)
        print(f"    '{m[:40]}' -> valid={v}")
        assert v

    print("\n[6] Multiplicative Forgery Attack Demo...")
    valid_raw, valid_hashed = demo_multiplicative_forgery(bits=256)
    assert valid_raw, "Raw RSA should be forgeable"
    assert not valid_hashed, "Hash-then-sign should resist forgery"

    print("\n[7] EUF-CMA Security Game...")
    game = EUF_CMA_Game(bits=512)
    successes = game.run_naive_adversary(num_queries=50)
    assert successes == 0, f"Expected 0 forgeries, got {successes}"

    print("\n[8] Schnorr Signature Scheme (DLP-based)...")
    print("    Initialising Schnorr parameters (128-bit)...")
    schnorr = SchnorrSignature(bits=128)
    x_schnorr, y_schnorr = schnorr.keygen()
    m_schnorr = b"Schnorr test message"
    sig_schnorr = schnorr.sign(x_schnorr, m_schnorr)
    v_schnorr = schnorr.verify(y_schnorr, m_schnorr, sig_schnorr)
    print(f"    Signature (e, s) = ({sig_schnorr[0]}, {sig_schnorr[1]})")
    print(f"    Valid: {v_schnorr}")
    assert v_schnorr, "Schnorr signature failed!"

    tampered_s = b"Schnorr test message TAMPERED"
    v_tampered_s = schnorr.verify(y_schnorr, tampered_s, sig_schnorr)
    print(f"    Tampered Schnorr valid: {v_tampered_s}")
    assert not v_tampered_s

    print("\n" + "=" * 65)
    print("All PA#15 tests passed.")
    print("=" * 65)
