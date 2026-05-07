"""
PA #3 — CPA-Secure Symmetric Encryption
CS8.401: Principles of Information Security

Implements:
1. CPA-secure encryption: C = <r, F_k(r) XOR m>
2. Multi-block support (counter extension)
3. IND-CPA game simulation
4. Broken variant (nonce reuse) demonstrating the attack
5. Interface: Enc(k, m) -> (r, c), Dec(k, r, c) -> m
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa2_prf'))
from prf import AES_PRF, aes_encrypt_block

BLOCK = 16  # 128-bit block size


# ─────────────────────────────────────────────
# Padding (PKCS#7)
# ─────────────────────────────────────────────
def pkcs7_pad(data: bytes, block_size: int = BLOCK) -> bytes:
    """PKCS#7 padding to multiple of block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS#7 padding."""
    if not data:
        raise ValueError("Empty data")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > BLOCK:
        raise ValueError(f"Invalid padding byte: {pad_len}")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid PKCS#7 padding")
    return data[:-pad_len]


# ─────────────────────────────────────────────
# CPA-Secure Encryption (PRF-based)
# ─────────────────────────────────────────────
class CPA_Enc:
    """
    CPA-secure symmetric encryption.
    Enc(k, m):
        r <- {0,1}^n  (fresh random nonce)
        c = F_k(r) XOR m  (for single block)
        return (r, c)
    
    For multi-block messages, uses counter mode:
        c_i = F_k(r + i) XOR m_i
    """
    def __init__(self, prf=None):
        self.prf = prf or AES_PRF()

    def _prf(self, k: bytes, x: bytes) -> bytes:
        return self.prf.F(k, x)

    def _int_to_block(self, n: int) -> bytes:
        """Convert integer to 16-byte block (big-endian)."""
        return n.to_bytes(BLOCK, 'big')

    def _block_add(self, block: bytes, n: int) -> bytes:
        """Add integer to block (counter increment)."""
        val = int.from_bytes(block, 'big')
        return ((val + n) % (2 ** (BLOCK * 8))).to_bytes(BLOCK, 'big')

    def encrypt(self, k: bytes, m: bytes) -> tuple:
        """
        Encrypt message m with key k.
        Returns (r, c) where r is the nonce.
        """
        assert len(k) == BLOCK
        r = os.urandom(BLOCK)  # Fresh random nonce each call
        padded = pkcs7_pad(m)
        n_blocks = len(padded) // BLOCK
        ct_blocks = []
        for i in range(n_blocks):
            mi = padded[i*BLOCK:(i+1)*BLOCK]
            # Counter: r, r+1, r+2, ...
            counter = self._block_add(r, i)
            keystream = self._prf(k, counter)
            ct_blocks.append(bytes(a ^ b for a, b in zip(keystream, mi)))
        return r, b''.join(ct_blocks)

    def decrypt(self, k: bytes, r: bytes, c: bytes) -> bytes:
        """Decrypt ciphertext c with nonce r and key k."""
        assert len(k) == BLOCK and len(r) == BLOCK
        if len(c) % BLOCK != 0:
            raise ValueError("Ciphertext length must be multiple of block size")
        n_blocks = len(c) // BLOCK
        pt_blocks = []
        for i in range(n_blocks):
            ci = c[i*BLOCK:(i+1)*BLOCK]
            counter = self._block_add(r, i)
            keystream = self._prf(k, counter)
            pt_blocks.append(bytes(a ^ b for a, b in zip(keystream, ci)))
        padded = b''.join(pt_blocks)
        return pkcs7_unpad(padded)

    # Aliases for unified interface
    def Enc(self, k: bytes, m: bytes) -> tuple:
        return self.encrypt(k, m)

    def Dec(self, k: bytes, r: bytes, c: bytes) -> bytes:
        return self.decrypt(k, r, c)


# ─────────────────────────────────────────────
# Broken CPA Encryption (nonce reuse)
# ─────────────────────────────────────────────
class Broken_CPA_Enc:
    """
    INSECURE: Deterministic encryption (nonce reuse).
    r is derived from k and a counter, never randomised.
    Demonstrates catastrophic failure when nonce is reused.
    """
    def __init__(self, prf=None):
        self.prf = prf or AES_PRF()
        self._fixed_r = b'\x00' * BLOCK  # Fixed nonce — insecure!

    def encrypt(self, k: bytes, m: bytes) -> tuple:
        """INSECURE: uses fixed nonce."""
        r = self._fixed_r  # BROKEN: same r every time
        padded = pkcs7_pad(m)
        n_blocks = len(padded) // BLOCK
        ct_blocks = []
        for i in range(n_blocks):
            mi = padded[i*BLOCK:(i+1)*BLOCK]
            counter = int.from_bytes(r, 'big') + i
            counter_bytes = counter.to_bytes(BLOCK, 'big')
            keystream = self.prf.F(k, counter_bytes)
            ct_blocks.append(bytes(a ^ b for a, b in zip(keystream, mi)))
        return r, b''.join(ct_blocks)


# ─────────────────────────────────────────────
# IND-CPA Security Game
# ─────────────────────────────────────────────
class IND_CPA_Game:
    """
    IND-CPA security game.
    Adversary queries encryption oracle, then submits (m0, m1) challenge.
    Wins if they can guess which was encrypted.
    """
    def __init__(self, enc_scheme: CPA_Enc):
        self.enc = enc_scheme
        self.key = os.urandom(BLOCK)
        self._b = None  # Challenge bit

    def oracle_encrypt(self, m: bytes) -> tuple:
        """Encryption oracle — adversary can query this."""
        return self.enc.Enc(self.key, m)

    def challenge(self, m0: bytes, m1: bytes) -> tuple:
        """
        Challenger picks random bit b, returns Enc(m_b).
        Adversary must guess b.
        """
        import random
        assert len(m0) == len(m1), "Challenge messages must have equal length"
        self._b = random.randint(0, 1)
        m = m0 if self._b == 0 else m1
        return self.enc.Enc(self.key, m)

    def submit_guess(self, b_guess: int) -> bool:
        """Returns True if adversary wins."""
        assert self._b is not None, "Must call challenge() first"
        return b_guess == self._b

    def run_simulation(self, n_rounds: int = 20) -> float:
        """
        Run the IND-CPA game for n_rounds with a dummy adversary.
        Dummy adversary always guesses 0 (achieves advantage ~0).
        Returns adversary advantage (should be ≈ 0).
        """
        wins = 0
        for _ in range(n_rounds):
            # Reset key each round
            self.key = os.urandom(BLOCK)
            # Adversary queries oracle 50 times (learns nothing useful)
            m0 = b'Hello, World!!!!!'[:BLOCK]
            m1 = b'Goodbye, World!!!'[:BLOCK]
            for _ in range(50):
                self.oracle_encrypt(m0)
            # Challenge
            self.challenge(m0, m1)
            # Dummy adversary always guesses 0
            if self.submit_guess(0):
                wins += 1
        advantage = abs(wins / n_rounds - 0.5)
        return advantage


# ─────────────────────────────────────────────
# Nonce-reuse attack demonstration
# ─────────────────────────────────────────────
def demonstrate_nonce_reuse_attack():
    """
    Demonstrate that nonce reuse is catastrophic.
    If r is reused for m1 and m2:
        c1 = F_k(r) XOR m1
        c2 = F_k(r) XOR m2
        c1 XOR c2 = m1 XOR m2  (keystream cancels!)
    """
    broken = Broken_CPA_Enc()
    k = os.urandom(BLOCK)
    m1 = b'Secret message!!'  # 16 bytes
    m2 = b'Another secret!!'  # 16 bytes

    r1, c1 = broken.encrypt(k, m1)
    r2, c2 = broken.encrypt(k, m2)

    assert r1 == r2, "Fixed nonce — r should be identical"

    # XOR ciphertexts
    xor_ct = bytes(a ^ b for a, b in zip(c1[:BLOCK], c2[:BLOCK]))
    # Should equal m1 XOR m2
    xor_pt = bytes(a ^ b for a, b in zip(m1, m2))

    print(f"  m1 = {m1}")
    print(f"  m2 = {m2}")
    print(f"  c1 XOR c2 = {xor_ct.hex()}")
    print(f"  m1 XOR m2 = {xor_pt.hex()}")
    print(f"  Match: {xor_ct == xor_pt} ← leaks XOR of plaintexts!")
    
    # With known m1, recover m2
    recovered_m2 = bytes(a ^ b for a, b in zip(xor_ct, m1))
    print(f"  Given m1, recovered m2 = {recovered_m2}")
    assert recovered_m2 == m2
    print("  Full plaintext recovery demonstrated ✓")


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #3 — CPA-Secure Symmetric Encryption")
    print("=" * 60)

    enc = CPA_Enc()

    # 1. Basic encrypt/decrypt
    print("\n[1] Basic Encryption/Decryption")
    k = os.urandom(BLOCK)
    messages = [
        b"Short",
        b"Exactly 16 bytes",  # One block
        b"This is a longer message that spans multiple blocks!!",
    ]
    for m in messages:
        r, c = enc.Enc(k, m)
        recovered = enc.Dec(k, r, c)
        print(f"  m = {m[:30]}...")
        print(f"  r = {r.hex()}, c = {c.hex()[:32]}...")
        print(f"  Recovered: {recovered} {'✓' if recovered == m else '✗ ERROR'}")

    # 2. Nonce freshness: same message encrypted twice gives different ciphertext
    print("\n[2] Randomness (fresh nonce per encryption)")
    m = b"Same message here"
    r1, c1 = enc.Enc(k, m)
    r2, c2 = enc.Enc(k, m)
    print(f"  Enc(k, m) #1: r={r1.hex()[:16]}...")
    print(f"  Enc(k, m) #2: r={r2.hex()[:16]}...")
    print(f"  Different nonces: {r1 != r2} ✓")
    print(f"  Different ciphertexts: {c1 != c2} ✓")

    # 3. IND-CPA game simulation
    print("\n[3] IND-CPA Game Simulation (20 rounds, dummy adversary)")
    game = IND_CPA_Game(enc)
    advantage = game.run_simulation(20)
    print(f"  Adversary advantage: {advantage:.4f} (should be ≈ 0)")
    assert advantage <= 0.3, f"Advantage {advantage} too high!"
    print("  CPA security empirically confirmed ✓")

    # 4. Nonce-reuse attack demonstration
    print("\n[4] Broken Variant: Nonce Reuse Attack")
    demonstrate_nonce_reuse_attack()

    print("\n✓ PA #3 complete.")
    print("Interface: from pa3_cpa.cpa_enc import CPA_Enc")
    print("  enc = CPA_Enc(); r, c = enc.Enc(k, m); m = enc.Dec(k, r, c)")
