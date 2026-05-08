"""
PA #17 — CCA-Secure Public-Key Cryptography
CS8.401: Principles of Information Security

Implements:
1. Signcryption: CCA_PKC_Enc(pk_enc, sk_sign, m) = (CE, sigma)
     - Encrypt with ElGamal (PA#16), then Sign the ciphertext (PA#15)
2. Verify-then-Decrypt: CCA_PKC_Dec(sk_enc, vk_sign, CE, sigma)
     - Verify signature FIRST; reject with ⊥ on failure; then decrypt
3. IND-CCA2 game: adversary gets encryption + decryption oracles
4. Contrast with plain ElGamal: malleability attack blocked by signature
5. Full lineage: PA#17 → PA#15 + PA#16 → PA#12 + PA#11 → PA#13

Dependencies:
  PA#15 (signatures.py)   — Sign / Verify
  PA#16 (elgamal.py)      — ElGamal Enc / Dec
  PA#12 (rsa.py)          — RSA key gen (used by PA#15)
  PA#13 (miller_rabin.py) — primality (used by PA#12)

No external cryptographic libraries used.
"""

import os
import sys
import random
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa15_signatures'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa16_elgamal'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa12_rsa'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa13_miller_rabin'))

from Q15_signatures import Sign, Verify, sig_keygen
from Q16_elgamal import (ElGamalParams, elgamal_keygen, ElGamal_Enc, ElGamal_Dec,
                     malleability_attack_multiply)
from Q13_miller_rabin import mod_exp


# ---------------------------------------------------------------------------
# Helper: serialise ElGamal ciphertext to bytes (for signing)
# ---------------------------------------------------------------------------

def _ciphertext_to_bytes(c1: int, c2: int) -> bytes:
    """Convert ElGamal ciphertext (c1, c2) to a canonical byte string for signing."""
    c1_bytes = c1.to_bytes((c1.bit_length() + 7) // 8 or 1, 'big')
    c2_bytes = c2.to_bytes((c2.bit_length() + 7) // 8 or 1, 'big')
    # length-prefixed encoding to avoid ambiguity
    return (len(c1_bytes).to_bytes(4, 'big') + c1_bytes +
            len(c2_bytes).to_bytes(4, 'big') + c2_bytes)


# ---------------------------------------------------------------------------
# Key Setup
# ---------------------------------------------------------------------------

def cca_pkc_setup(elgamal_bits: int = 128, sig_bits: int = 512):
    """
    Generate all keys needed for CCA-secure PKC.

    Returns:
      (elgamal_params, pk_enc, sk_enc,   # ElGamal encryption keys
       vk_sign, sk_sign)                  # RSA signature keys

    The encryption key pair is for ElGamal.
    The signing key pair is for RSA hash-then-sign (PA#15).
    These are INDEPENDENT key pairs (different mathematical objects).
    """
    # ElGamal encryption key pair (PA#16)
    elgamal_params = ElGamalParams(bits=elgamal_bits)
    pk_enc, sk_enc = elgamal_keygen(elgamal_params)

    # RSA signing key pair (PA#15 / PA#12)
    sk_sign, vk_sign = sig_keygen(bits=sig_bits)

    return elgamal_params, pk_enc, sk_enc, vk_sign, sk_sign


# ---------------------------------------------------------------------------
# CCA-Secure PKC Encryption (Encrypt-then-Sign)
# ---------------------------------------------------------------------------

def CCA_PKC_Enc(pk_enc, sk_sign, m: int) -> tuple:
    """
    CCA-Secure PKC Encryption via Encrypt-then-Sign (Signcryption).

    Steps:
      1. CE = ElGamal_Enc(pk_enc, m)     — PA#16 encryption
      2. sigma = Sign(sk_sign, bytes(CE)) — PA#15 signature over the ciphertext
      3. Return (CE, sigma) = ((c1, c2), sigma)

    Security: The signature binds CE to the sender's identity.
    Any modification to CE invalidates sigma, causing decryption to fail with ⊥.
    This prevents the CCA adversary from exploiting a decryption oracle on
    modified ciphertexts.
    """
    # Step 1: ElGamal encryption
    c1, c2 = ElGamal_Enc(pk_enc, m)
    CE = (c1, c2)

    # Step 2: Sign the ciphertext bytes (not the plaintext)
    CE_bytes = _ciphertext_to_bytes(c1, c2)
    sigma = Sign(sk_sign, CE_bytes)

    return CE, sigma


# ---------------------------------------------------------------------------
# CCA-Secure PKC Decryption (Verify-then-Decrypt)
# ---------------------------------------------------------------------------

REJECTION_SYMBOL = None  # ⊥

def CCA_PKC_Dec(pk_enc, sk_enc, vk_sign, CE: tuple, sigma: int):
    """
    CCA-Secure PKC Decryption via Verify-then-Decrypt.

    Steps:
      1. Verify signature: Verify(vk_sign, bytes(CE), sigma)
         — If INVALID: return ⊥  (MUST reject BEFORE any decryption attempt)
      2. Decrypt: ElGamal_Dec(pk_enc, sk_enc, c1, c2)
      3. Return plaintext m

    Critical ordering: verification PRECEDES decryption.
    If we decrypted first, a CCA adversary could modify CE and learn information
    about the plaintext from the decryption oracle. The signature check eliminates
    this attack vector entirely.

    Returns: plaintext integer m, or None (⊥) if signature invalid.
    """
    c1, c2 = CE
    CE_bytes = _ciphertext_to_bytes(c1, c2)

    # Step 1: Verify signature BEFORE decrypting (mandatory ordering)
    if not Verify(vk_sign, CE_bytes, sigma):
        return REJECTION_SYMBOL  # ⊥ — tampered ciphertext rejected

    # Step 2: Decrypt only if signature is valid
    m = ElGamal_Dec(pk_enc, sk_enc, c1, c2)
    return m


# ---------------------------------------------------------------------------
# IND-CCA2 Game
# ---------------------------------------------------------------------------

class IND_CCA2_Game:
    """
    IND-CCA2 (Adaptive Chosen-Ciphertext Attack) Game for CCA-PKC.

    The adversary has access to both:
      - Encryption oracle: Enc(m) -> (CE, sigma)
      - Decryption oracle: Dec(CE, sigma) -> m or ⊥
        (the challenge ciphertext is excluded from decryption oracle)

    Phases:
      Phase 1: Adversary may query Enc and Dec freely.
      Challenge: Adversary submits (m0, m1); challenger returns (CE*, sigma*)
                 for random m_b.
      Phase 2: Adversary may continue querying Enc and Dec (not on CE*).
      Guess: Adversary outputs b' in {0, 1}.
      Win condition: b' == b.
      Advantage = |Pr[win] - 1/2|. Secure scheme => advantage ≈ 0.
    """

    def __init__(self, elgamal_params: ElGamalParams = None, bits: int = 128):
        if elgamal_params is None:
            elgamal_params = ElGamalParams(bits)
        self.params = elgamal_params
        (self.params_eg, self.pk_enc, self.sk_enc,
         self.vk_sign, self.sk_sign) = cca_pkc_setup(
            elgamal_bits=bits, sig_bits=512)
        self._b = None
        self._challenge = None

    def enc_oracle(self, m: int) -> tuple:
        return CCA_PKC_Enc(self.pk_enc, self.sk_sign, m)

    def dec_oracle(self, CE: tuple, sigma: int):
        """Decryption oracle. Rejects the challenge ciphertext (if challenge sent)."""
        if self._challenge is not None and CE == self._challenge[0]:
            print("  [GAME] Adversary submitted challenge ciphertext to dec oracle — REJECTED")
            return REJECTION_SYMBOL
        return CCA_PKC_Dec(self.pk_enc, self.sk_enc, self.vk_sign, CE, sigma)

    def challenge(self, m0: int, m1: int) -> tuple:
        self._b = random.randint(0, 1)
        m_b = m0 if self._b == 0 else m1
        CE_star, sigma_star = CCA_PKC_Enc(self.pk_enc, self.sk_sign, m_b)
        self._challenge = (CE_star, sigma_star)
        return CE_star, sigma_star

    def guess(self, b_prime: int) -> bool:
        assert self._challenge is not None
        return b_prime == self._b

    def run_dummy_adversary(self, num_trials: int = 50):
        """
        Dummy adversary: queries oracles, attempts malleability, then guesses randomly.
        Expected advantage: ≈ 0.
        """
        print(f"\n=== IND-CCA2 Game: Dummy Adversary ({num_trials} trials) ===")
        wins = 0
        for trial in range(num_trials):
            # Phase 1: Get some encryptions
            m0 = self.params_eg.random_element()
            m1 = self.params_eg.random_element()
            while m1 == m0:
                m1 = self.params_eg.random_element()

            # Get challenge
            CE_star, sigma_star = self.challenge(m0, m1)
            c1_star, c2_star = CE_star

            # Attempt: modify CE_star and query decryption oracle
            # This should return ⊥ because the signature on the modified CE is invalid
            c2_modified = (2 * c2_star) % self.pk_enc[0]
            CE_modified = (c1_star, c2_modified)
            result = self.dec_oracle(CE_modified, sigma_star)
            # result should be ⊥ because sigma_star is invalid for CE_modified
            if result is not REJECTION_SYMBOL:
                print(f"  [WARN] Trial {trial}: Modified ciphertext was NOT rejected!")

            # Random guess
            b_guess = random.randint(0, 1)
            if self.guess(b_guess):
                wins += 1
            self._challenge = None

        advantage = abs(wins / num_trials - 0.5)
        print(f"  Wins: {wins}/{num_trials}")
        print(f"  Advantage: {advantage:.4f} (expected ≈ 0)")
        return advantage


# ---------------------------------------------------------------------------
# Contrast: malleability attack on plain ElGamal (no signature) vs CCA-PKC
# ---------------------------------------------------------------------------

def demo_cca_vs_plain_elgamal(params: ElGamalParams = None, bits: int = 128):
    """
    Side-by-side comparison:
    - Plain ElGamal: malleability attack succeeds
    - CCA-PKC (Encrypt-then-Sign): malleability attack is blocked by signature check
    """
    print("\n=== CCA-PKC vs Plain ElGamal: Malleability Attack ===")
    if params is None:
        params = ElGamalParams(bits)

    pk_enc, sk_enc = elgamal_keygen(params)
    sk_sign, vk_sign = sig_keygen(bits=512)
    p = params.p

    m = params.random_element()
    print(f"  Original message m = {m}")

    # --- Plain ElGamal: attack succeeds ---
    print("\n  [Plain ElGamal]")
    c1, c2 = ElGamal_Enc(pk_enc, m)
    print(f"  Ciphertext: c1={c1}, c2={c2}")
    # Adversary modifies: multiply c2 by 2
    c1_mod, c2_mod = malleability_attack_multiply(pk_enc, c1, c2, 2)
    m_dec_plain = ElGamal_Dec(pk_enc, sk_enc, c1_mod, c2_mod)
    print(f"  Dec(c1, 2*c2) = {m_dec_plain}")
    print(f"  == 2*m? {m_dec_plain == (2 * m) % p} → ATTACK SUCCEEDED (malleability confirmed)")

    # --- CCA-PKC Encrypt-then-Sign: attack blocked ---
    print("\n  [CCA-PKC: Encrypt-then-Sign]")
    CE, sigma = CCA_PKC_Enc(pk_enc, sk_sign, m)
    c1_cca, c2_cca = CE
    print(f"  Ciphertext: c1={c1_cca}, c2={c2_cca}")
    print(f"  Signature:  sigma={sigma}")

    # Adversary modifies CE (multiply c2 by 2) and reuses old sigma
    CE_tampered = (c1_cca, (2 * c2_cca) % p)
    result = CCA_PKC_Dec(pk_enc, sk_enc, vk_sign, CE_tampered, sigma)
    print(f"  Dec(tampered CE, old sigma) = {result} (⊥ means rejected)")
    print(f"  Attack blocked: {result is REJECTION_SYMBOL}")
    assert result is REJECTION_SYMBOL, "CCA-PKC should reject tampered ciphertext!"

    # Valid decryption still works
    m_valid = CCA_PKC_Dec(pk_enc, sk_enc, vk_sign, CE, sigma)
    print(f"\n  Valid decryption: {m_valid == m}")
    assert m_valid == m, "Valid ciphertext decryption failed!"

    return True


# ---------------------------------------------------------------------------
# Full lineage verification
# ---------------------------------------------------------------------------

def verify_lineage():
    """
    Verify and demonstrate the full dependency chain:
    PA#17 → PA#15 (Sign/Verify) → PA#12 (RSA keygen) → PA#13 (Miller-Rabin)
    PA#17 → PA#16 (ElGamal Enc/Dec) → PA#11 (DH group) → PA#13 (Miller-Rabin)
    """
    print("\n=== Full Lineage Verification ===")
    print("  PA#17 (CCA-PKC)")
    print("    ├─ PA#15 (Digital Signatures)")
    print("    │    └─ PA#12 (RSA keygen, fast_modexp)")
    print("    │         └─ PA#13 (Miller-Rabin, gen_prime)")
    print("    └─ PA#16 (ElGamal Enc/Dec)")
    print("         └─ PA#11 (DH group: safe prime, generator)")
    print("              └─ PA#13 (Miller-Rabin, gen_safe_prime)")

    # Trigger the chain by running a full encrypt-decrypt cycle
    from Q13_miller_rabin import  gen_safe_prime
    from Q12_rsa import rsa_keygen, fast_modexp
    # These imports confirm the chain is intact at import time.
    print("\n  All dependencies loaded from own implementations. ✓")


# ---------------------------------------------------------------------------
# Self-test / demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 65)
    print("PA #17 — CCA-Secure Public-Key Cryptography")
    print("=" * 65)

    print("\n[1] Setting up CCA-PKC keys (ElGamal 128-bit, RSA-sig 512-bit)...")
    t0 = time.time()
    (eg_params, pk_enc, sk_enc,
     vk_sign, sk_sign) = cca_pkc_setup(elgamal_bits=128, sig_bits=512)
    print(f"    Setup time: {time.time()-t0:.3f}s")

    print("\n[2] Encrypt and Decrypt a message...")
    m = eg_params.random_element()
    print(f"    Plaintext m = {m}")
    CE, sigma = CCA_PKC_Enc(pk_enc, sk_sign, m)
    c1, c2 = CE
    print(f"    Ciphertext CE = (c1={c1}, c2={c2})")
    print(f"    Signature sigma = {sigma}")

    m_dec = CCA_PKC_Dec(pk_enc, sk_enc, vk_sign, CE, sigma)
    print(f"    Decrypted m = {m_dec}")
    print(f"    Correct: {m_dec == m}")
    assert m_dec == m, "Decryption failed!"

    print("\n[3] Tampered ciphertext returns ⊥...")
    p = pk_enc[0]
    CE_tampered = (c1, (c2 + 1) % p)
    result_tampered = CCA_PKC_Dec(pk_enc, sk_enc, vk_sign, CE_tampered, sigma)
    print(f"    Dec(tampered CE) = {result_tampered}")
    print(f"    Correctly returns ⊥: {result_tampered is REJECTION_SYMBOL}")
    assert result_tampered is REJECTION_SYMBOL

    print("\n[4] Invalid signature returns ⊥...")
    bad_sigma = sigma ^ (1 << 5)
    result_badsig = CCA_PKC_Dec(pk_enc, sk_enc, vk_sign, CE, bad_sigma)
    print(f"    Dec(CE, bad_sigma) = {result_badsig}")
    assert result_badsig is REJECTION_SYMBOL

    print("\n[5] Malleability Attack Comparison...")
    demo_cca_vs_plain_elgamal(eg_params)

    print("\n[6] IND-CCA2 Game (dummy adversary, 50 trials)...")
    game = IND_CCA2_Game(bits=128)
    adv = game.run_dummy_adversary(num_trials=50)
    print(f"    Advantage: {adv:.4f} (expected ≈ 0)")
    assert adv < 0.15, f"Advantage {adv} too large!"

    print("\n[7] Full lineage verification...")
    verify_lineage()

    print("\n" + "=" * 65)
    print("All PA#17 tests passed.")
    print("=" * 65)
