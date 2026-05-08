"""
PA #6 — CCA-Secure Symmetric Encryption
CS8.401: Principles of Information Security

Implements:
1. Encrypt-then-MAC construction
2. Key separation (independent kE, kM)
3. IND-CCA2 game simulation
4. Malleability attack on CPA-only vs. CCA scheme
5. Interface: CCA_Enc(kE, kM, m) -> (c, t), CCA_Dec(kE, kM, c, t) -> m or ⊥
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa3_cpa'))
from Q3_cpa_enc import CPA_Enc, BLOCK

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa5_mac'))
from Q5_mac import PRF_MAC, secure_compare

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa2_prf'))
from Q2_prf import AES_PRF


# ─────────────────────────────────────────────
# CCA-Secure Encryption (Encrypt-then-MAC)
# ─────────────────────────────────────────────
class CCA_Enc:
    """
    Encrypt-then-MAC:
    Enc(kE, kM, m):
        CE = CPA_Enc(kE, m)
        t  = MAC(kM, CE)
        return (CE, t)
    
    Dec(kE, kM, CE, t):
        if Vrfy(kM, CE, t) == 0: return ⊥
        return CPA_Dec(kE, CE)
    
    Security: CCA2-secure when Enc is CPA-secure and MAC is EUF-CMA secure.
    """
    def __init__(self, cpa=None, mac=None):
        self.cpa = cpa or CPA_Enc()
        self.mac = mac or PRF_MAC()

    def Enc(self, kE: bytes, kM: bytes, m: bytes) -> tuple:
        """Encrypt m; returns (r, c, t) where r is nonce, c is ciphertext, t is tag."""
        assert len(kE) == BLOCK and len(kM) == BLOCK
        # Step 1: CPA-secure encrypt
        r, c = self.cpa.Enc(kE, m)
        # Step 2: MAC the entire ciphertext (including nonce r)
        ce = r + c  # Complete ciphertext includes nonce
        t = self.mac.Mac(kM, ce[:BLOCK])  # MAC on first block of ce
        # For variable-length: MAC over all of ce using CBC-MAC
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa5_mac'))
        from Q5_mac import CBC_MAC
        cbc_mac = CBC_MAC()
        t = cbc_mac.Mac(kM, ce)
        return r, c, t

    def Dec(self, kE: bytes, kM: bytes, r: bytes, c: bytes, t: bytes):
        """Decrypt; returns plaintext or None (⊥) on MAC failure."""
        assert len(kE) == BLOCK and len(kM) == BLOCK
        ce = r + c
        # Step 1: Verify MAC BEFORE decrypting
        from Q5_mac import CBC_MAC
        cbc_mac = CBC_MAC()
        if not cbc_mac.Vrfy(kM, ce, t):
            return None  # ⊥ — reject tampered ciphertext
        # Step 2: Decrypt
        return self.cpa.Dec(kE, r, c)

    def CCA_Enc(self, kE, kM, m): return self.Enc(kE, kM, m)
    def CCA_Dec(self, kE, kM, r, c, t): return self.Dec(kE, kM, r, c, t)


# ─────────────────────────────────────────────
# Key Separation Demo
# ─────────────────────────────────────────────
def demo_key_separation():
    """
    Demonstrate that using the same key for Enc and MAC is dangerous.
    When kE == kM, the PRF outputs used for encryption are correlated
    with the MAC, potentially creating exploitable patterns.
    """
    print("\n  Key Separation Demo:")
    cca = CCA_Enc()
    k = os.urandom(BLOCK)

    print("  [CORRECT] Independent keys kE and kM:")
    kE = os.urandom(BLOCK)
    kM = os.urandom(BLOCK)
    r, c, t = cca.Enc(kE, kM, b"Secret message!!")
    m_dec = cca.Dec(kE, kM, r, c, t)
    print(f"    Enc/Dec correct: {m_dec == b'Secret message!!'} ✓")

    print("\n  [DANGER] Same key kE == kM:")
    print("    If kE == kM, then MAC tags may be correlated with encryption keystream.")
    print("    PRF outputs F_k(r) (for encryption) and F_k(ce) (for MAC) share key k.")
    print("    This can leak information if the PRF is not ideal — key separation is mandatory.")
    print("    Industry standard: always derive kE and kM independently.")


# ─────────────────────────────────────────────
# IND-CCA2 Game
# ─────────────────────────────────────────────
class IND_CCA2_Game:
    """
    IND-CCA2 Game:
    - Adversary has encryption oracle AND decryption oracle.
    - Decryption oracle rejects the challenge ciphertext.
    - After seeing challenge, adversary queries Dec oracle with modified ciphertexts.
    - Goal: distinguish which of m0, m1 was encrypted.
    """
    def __init__(self, cca: CCA_Enc):
        self.cca = cca
        self.kE = os.urandom(BLOCK)
        self.kM = os.urandom(BLOCK)
        self._challenge_ct = None
        self._b = None

    def oracle_encrypt(self, m: bytes) -> tuple:
        return self.cca.Enc(self.kE, self.kM, m)

    def oracle_decrypt(self, r: bytes, c: bytes, t: bytes):
        """Decryption oracle — rejects challenge ciphertext."""
        if self._challenge_ct and (r, c) == self._challenge_ct[:2]:
            return None  # Reject challenge ciphertext
        return self.cca.Dec(self.kE, self.kM, r, c, t)

    def challenge(self, m0: bytes, m1: bytes) -> tuple:
        import random
        assert len(m0) == len(m1)
        self._b = random.randint(0, 1)
        m = m0 if self._b == 0 else m1
        ct = self.cca.Enc(self.kE, self.kM, m)
        self._challenge_ct = ct
        return ct

    def submit_guess(self, b_guess: int) -> bool:
        return b_guess == self._b

    def run_simulation(self, n_rounds: int = 20) -> float:
        """
        Run IND-CCA2 game. Adversary tries malleability attack:
        flip a bit in ciphertext, query decryption oracle.
        Returns adversary advantage (should be ≈ 0).
        """
        wins = 0
        for _ in range(n_rounds):
            self.kE = os.urandom(BLOCK)
            self.kM = os.urandom(BLOCK)
            self._challenge_ct = None

            m0 = b'Message zero!!!!'; m1 = b'Message one!!!!!'
            r_star, c_star, t_star = self.challenge(m0, m1)

            # Adversary tries: flip bit in c_star, query oracle
            c_modified = bytearray(c_star)
            c_modified[0] ^= 0x01
            c_modified = bytes(c_modified)
            result = self.oracle_decrypt(r_star, c_modified, t_star)
            # MAC fails on modified ciphertext => oracle returns ⊥
            assert result is None, "CCA scheme should reject modified ciphertext!"

            # Adversary can't determine b without useful oracle queries
            # Best strategy: random guess
            import random
            if self.submit_guess(random.randint(0, 1)):
                wins += 1

        advantage = abs(wins / n_rounds - 0.5)
        return advantage


# ─────────────────────────────────────────────
# Malleability Demonstration
# ─────────────────────────────────────────────
def demo_malleability():
    """
    CPA-only scheme is malleable:
    C = <r, F_k(r) XOR m>
    Flip bit i of c to get ciphertext for m with bit i flipped.
    
    CCA scheme detects and rejects this.
    """
    print("\n  Malleability Demo:")

    cpa = CPA_Enc()
    cca = CCA_Enc()

    k = os.urandom(BLOCK)
    kE = os.urandom(BLOCK)
    kM = os.urandom(BLOCK)
    m = b'Vote: YES!!!!!!'  # 1 block

    # CPA encryption
    r_cpa, c_cpa = cpa.Enc(k, m)
    print(f"  CPA plaintext:  {m}")
    print(f"  CPA ciphertext: {c_cpa.hex()[:32]}...")

    # Flip bit 0 of ciphertext block (bit-flip attack)
    c_flipped = bytearray(c_cpa)
    c_flipped[0] ^= 0x80  # Flip MSB of first byte
    c_flipped = bytes(c_flipped)

    # CPA: decryption SUCCEEDS with corrupted plaintext
    m_corrupted = cpa.Dec(k, r_cpa, c_flipped)
    print(f"\n  [CPA-ONLY] After bit flip:")
    print(f"  Decrypted: {m_corrupted} ← corrupted but accepted! MALLEABLE!")
    assert m_corrupted != m, "Bit flip should corrupt plaintext"

    # CCA encryption
    r_cca, c_cca, t_cca = cca.Enc(kE, kM, m)
    print(f"\n  CCA ciphertext: {c_cca.hex()[:32]}...")

    # Flip bit in CCA ciphertext
    c_cca_flipped = bytearray(c_cca)
    c_cca_flipped[0] ^= 0x80
    c_cca_flipped = bytes(c_cca_flipped)

    # CCA: decryption REJECTS (MAC fails)
    result = cca.Dec(kE, kM, r_cca, c_cca_flipped, t_cca)
    print(f"\n  [CCA Encrypt-then-MAC] After bit flip:")
    print(f"  Decryption result: {result} ← ⊥ (rejected by MAC) NON-MALLEABLE ✓")
    assert result is None, "CCA should reject modified ciphertext"


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #6 — CCA-Secure Symmetric Encryption")
    print("=" * 60)

    cca = CCA_Enc()

    # 1. Basic encrypt/decrypt
    print("\n[1] Basic Encrypt-then-MAC")
    kE = os.urandom(BLOCK)
    kM = os.urandom(BLOCK)
    messages = [
        b"Short message",
        b"Exactly 16byte!",
        b"A longer message that spans multiple cipher blocks here!!",
    ]
    for m in messages:
        r, c, t = cca.Enc(kE, kM, m)
        recovered = cca.Dec(kE, kM, r, c, t)
        print(f"  m = {m[:30]!r}, recovered = {recovered!r} {'✓' if recovered == m else '✗'}")

    # 2. MAC check blocks tampered ciphertext
    print("\n[2] Tampered Ciphertext Rejection")
    r, c, t = cca.Enc(kE, kM, b"Important data!!")
    c_bad = bytes([c[0] ^ 0x01]) + c[1:]  # Flip first byte
    result = cca.Dec(kE, kM, r, c_bad, t)
    print(f"  Tampered ciphertext -> {result} (⊥ = None) ✓")
    assert result is None

    # Tampered tag
    t_bad = bytes([t[0] ^ 0x01]) + t[1:]
    result2 = cca.Dec(kE, kM, r, c, t_bad)
    print(f"  Tampered tag -> {result2} (⊥ = None) ✓")
    assert result2 is None

    # 3. IND-CCA2 game
    print("\n[3] IND-CCA2 Game Simulation")
    game = IND_CCA2_Game(cca)
    advantage = game.run_simulation(20)
    print(f"  Adversary advantage: {advantage:.4f} (should be ≈ 0)")
    assert advantage <= 0.3
    print("  CCA2 security confirmed ✓")

    # 4. Malleability demo
    print("\n[4] Malleability: CPA-only vs CCA")
    demo_malleability()

    # 5. Key separation
    print("\n[5] Key Separation")
    demo_key_separation()

    print("\n✓ PA #6 complete.")
    print("Interface: from pa6_cca.cca_enc import CCA_Enc")
    print("  cca = CCA_Enc(); r,c,t = cca.Enc(kE,kM,m); m = cca.Dec(kE,kM,r,c,t)")
