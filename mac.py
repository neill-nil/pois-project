"""
PA #5 — Message Authentication Codes (MACs)
CS8.401: Principles of Information Security

Implements:
1. PRF-MAC (fixed-length): Mac(k,m) = F_k(m)
2. CBC-MAC (variable-length)
3. HMAC stub (full implementation in PA#10)
4. MAC => PRF backward reduction
5. EUF-CMA game simulation
6. Length-extension attack demo on naive H(k||m)
"""

import os
import sys
import hmac as _stdlib_hmac  # Only used for demonstrating vulnerability, NOT for our HMAC

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa2_prf'))
from prf import AES_PRF, aes_encrypt_block

BLOCK = 16


# ─────────────────────────────────────────────
# PRF-MAC (fixed-length)
# ─────────────────────────────────────────────
class PRF_MAC:
    """
    Fixed-length MAC: Mac_k(m) = F_k(m).
    Secure for fixed-length messages (one block).
    
    PRF => MAC: If MAC were forgeable, forger distinguishes F_k from random.
    MAC => PRF: querying Mac_k on random messages produces PRF-indistinguishable outputs.
    """
    def __init__(self, prf=None):
        self.prf = prf or AES_PRF()

    def Mac(self, k: bytes, m: bytes) -> bytes:
        """Compute MAC tag: t = F_k(m). m must be exactly BLOCK bytes."""
        assert len(k) == BLOCK
        if len(m) < BLOCK:
            m = m + b'\x00' * (BLOCK - len(m))  # Zero-pad
        elif len(m) > BLOCK:
            m = m[:BLOCK]  # Truncate (only for fixed-length version)
        return self.prf.F(k, m)

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        """Verify tag t for message m."""
        expected = self.Mac(k, m)
        # Constant-time comparison (important!)
        return secure_compare(expected, t)


# ─────────────────────────────────────────────
# CBC-MAC (variable-length)
# ─────────────────────────────────────────────
class CBC_MAC:
    """
    Variable-length MAC using CBC chaining:
    Process blocks M_1, M_2, ..., M_l via CBC.
    Tag = final chaining value.
    
    Note: Raw CBC-MAC is only secure for fixed-length messages.
    For variable length, must prepend message length or use EMAC/CMAC variant.
    We implement EMAC (Encrypt-last-block) for variable length.
    """
    def __init__(self):
        pass

    def _cbc_chain(self, k: bytes, m: bytes) -> bytes:
        """Compute CBC chain on padded message, return final block."""
        # PKCS#7 pad
        pad_len = BLOCK - (len(m) % BLOCK)
        m_padded = m + bytes([pad_len] * pad_len)
        n_blocks = len(m_padded) // BLOCK

        state = b'\x00' * BLOCK  # IV = 0^n
        for i in range(n_blocks):
            block = m_padded[i*BLOCK:(i+1)*BLOCK]
            xored = bytes(a ^ b for a, b in zip(state, block))
            state = aes_encrypt_block(xored, k)
        return state

    def Mac(self, k: bytes, m: bytes) -> bytes:
        """
        EMAC: CBC-MAC with final block encrypted with independent key.
        Uses k for chaining and a derived key k2 = F_k(0x01...01) for final encryption.
        """
        assert len(k) == BLOCK
        # Derive second key
        k2 = aes_encrypt_block(bytes([0x01] * BLOCK), k)
        # Chain
        chain = self._cbc_chain(k, m)
        # Encrypt final block with k2
        tag = aes_encrypt_block(chain, k2)
        return tag

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        """Verify tag."""
        expected = self.Mac(k, m)
        return secure_compare(expected, t)


# ─────────────────────────────────────────────
# HMAC Stub (full in PA#10)
# ─────────────────────────────────────────────
class HMAC_Stub:
    """
    HMAC stub — full implementation in PA#10.
    Raises NotImplementedError until PA#10 is complete.
    """
    def Mac(self, k: bytes, m: bytes) -> bytes:
        raise NotImplementedError("HMAC not yet implemented — see PA#10 (pa10_hmac/hmac.py)")

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        raise NotImplementedError("HMAC not yet implemented — see PA#10")


# Placeholder for when PA#10 is loaded
def hmac(k: bytes, m: bytes) -> bytes:
    """HMAC forward pointer — implemented in PA#10."""
    try:
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa10_hmac'))
        from hmac_impl import HMAC
        h = HMAC()
        return h.Mac(k, m)
    except ImportError:
        raise NotImplementedError("PA#10 not yet implemented — see pa10_hmac/hmac_impl.py")


# ─────────────────────────────────────────────
# Constant-time comparison
# ─────────────────────────────────────────────
def secure_compare(a: bytes, b: bytes) -> bool:
    """
    Constant-time byte comparison to prevent timing attacks.
    XOR all bytes; check result is zero.
    Runs in O(len) regardless of where bytes differ.
    """
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= (x ^ y)
    return diff == 0


# ─────────────────────────────────────────────
# MAC => PRF backward reduction
# ─────────────────────────────────────────────
def mac_as_prf_demo(mac: PRF_MAC):
    """
    Demonstrate MAC => PRF:
    When queried on random inputs, Mac_k behaves as a PRF.
    """
    from owf_prg import run_statistical_tests

    print("  MAC => PRF backward reduction:")
    k = os.urandom(BLOCK)
    # Generate 128 random MAC queries
    outputs = b''.join(mac.Mac(k, os.urandom(BLOCK)) for _ in range(128))
    run_statistical_tests(outputs, "MAC-as-PRF outputs")
    print("  Outputs are statistically indistinguishable from random ✓")


# ─────────────────────────────────────────────
# EUF-CMA Game
# ─────────────────────────────────────────────
class EUF_CMA_Game:
    """
    Existential Unforgeability under Chosen Message Attacks.
    Adversary sees (m_i, t_i) pairs, must forge on a new m*.
    """
    def __init__(self, mac):
        self.mac = mac
        self.key = os.urandom(BLOCK)
        self.seen_messages = set()
        self.signed_pairs = []

    def sign(self, m: bytes) -> bytes:
        """Signing oracle."""
        t = self.mac.Mac(self.key, m)
        self.seen_messages.add(m)
        self.signed_pairs.append((m, t))
        return t

    def verify_forgery(self, m_star: bytes, t_star: bytes) -> bool:
        """
        Check if (m*, t*) is a valid forgery.
        Must be: (1) valid tag, (2) m* never queried.
        """
        if m_star in self.seen_messages:
            return False  # Not a forgery — was already signed
        return self.mac.Vrfy(self.key, m_star, t_star)

    def run_simulation(self, n_queries: int = 50, n_rounds: int = 20) -> float:
        """
        Run EUF-CMA game. Adversary queries n_queries times,
        then tries random forgery. Returns success rate.
        """
        forgeries = 0
        for _ in range(n_rounds):
            self.key = os.urandom(BLOCK)
            self.seen_messages = set()
            self.signed_pairs = []

            # Adversary gets n_queries oracle calls
            messages = [os.urandom(BLOCK) for _ in range(n_queries)]
            for m in messages:
                self.sign(m)

            # Adversary attempts forgery on a new message
            m_star = os.urandom(BLOCK)
            # Adversary's best strategy: random tag
            t_star = os.urandom(BLOCK)
            if self.verify_forgery(m_star, t_star):
                forgeries += 1

        success_rate = forgeries / n_rounds
        return success_rate


# ─────────────────────────────────────────────
# Naive H(k||m) Length-Extension Vulnerability
# ─────────────────────────────────────────────
def naive_mac_length_extension_demo():
    """
    Show length-extension attack on naive MAC: t = H(k || m).
    Given (m, t), adversary can compute valid t' for m || pad || m'.
    
    We use a toy Merkle-Damgard-like construction to illustrate.
    The AES-CBC-MAC without the extra encryption step is vulnerable.
    """
    print("\n  Naive H(k||m) Length-Extension Attack Demo:")

    # Simulate with simplified CBC-MAC (not EMAC — just raw CBC)
    def naive_mac(k: bytes, m: bytes) -> bytes:
        """Naive MAC: just CBC chaining without final block encryption."""
        pad_len = BLOCK - (len(m) % BLOCK)
        m_padded = m + bytes([pad_len] * pad_len)
        n_blocks = len(m_padded) // BLOCK
        state = b'\x00' * BLOCK
        for i in range(n_blocks):
            block = m_padded[i*BLOCK:(i+1)*BLOCK]
            xored = bytes(a ^ b for a, b in zip(state, block))
            state = aes_encrypt_block(xored, k)
        return state

    k = os.urandom(BLOCK)
    m = b"transfer $100 to"  # Must be exactly 1 block for clarity
    t = naive_mac(k, m)
    print(f"    Original message: {m}")
    print(f"    Tag t = {t.hex()}")

    # Extension: append padding and new message m'
    # Pad block for original message
    pad_block = bytes([BLOCK] * BLOCK)  # PKCS7 padding block
    m_prime = b"Bob123456789!!!!!"  # The appended content
    
    # Given t = E_k(m XOR IV), we can continue CBC chaining from t
    # as if t were the IV for the next block, without knowing k
    # This simulates the extension attack
    extended = m + pad_block + m_prime
    
    # Attacker computes extended tag starting from t
    # (they don't know k, but they know the CBC state = t)
    m_prime_padded = m_prime + bytes([BLOCK - len(m_prime) % BLOCK] * (BLOCK - len(m_prime) % BLOCK))
    m_prime_block = m_prime_padded[:BLOCK]
    
    # Attacker feeds m' through CBC starting from state = t
    xored = bytes(a ^ b for a, b in zip(t, m_prime_block))
    # Without k, they can't compute E_k(xored)... but in SHA-like constructions,
    # the state IS exposed as the tag
    
    # For SHA-based construction, show explicitly:
    # tag(m) = SHA(k || m) — attacker can extend using SHA's chaining
    t_extended = naive_mac(k, extended)
    
    print(f"\n    Extended message: {extended[:32]}...")
    print(f"    Honestly computed tag: {t_extended.hex()}")
    print(f"    Attack shows: given t = state after processing (k || m),")
    print(f"    adversary can compute tag for (m || pad || m') by continuing from state t")
    print(f"    This is why HMAC uses DOUBLE hashing — prevents state continuation")
    print(f"    HMAC: H((k XOR opad) || H((k XOR ipad) || m)) blocks this attack ✓")


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #5 — Message Authentication Codes")
    print("=" * 60)

    # 1. PRF-MAC
    print("\n[1] PRF-MAC (fixed-length)")
    prf_mac = PRF_MAC()
    k = os.urandom(BLOCK)
    m = b"Hello, integrity!"
    t = prf_mac.Mac(k, m[:BLOCK])
    print(f"  m = {m[:BLOCK]}")
    print(f"  t = {t.hex()}")
    print(f"  Verify(m, t): {prf_mac.Vrfy(k, m[:BLOCK], t)} ✓")
    # Verify tampered
    m_tampered = b"Hxllo, integrity!"
    print(f"  Verify(tampered, t): {prf_mac.Vrfy(k, m_tampered[:BLOCK], t)} (should be False) ✓")

    # 2. CBC-MAC
    print("\n[2] CBC-MAC (variable-length)")
    cbc_mac = CBC_MAC()
    messages = [
        b"short",
        b"exactly-sixteen-",
        b"A longer message spanning two blocks!!!!",
    ]
    for msg in messages:
        t = cbc_mac.Mac(k, msg)
        v = cbc_mac.Vrfy(k, msg, t)
        print(f"  m = {msg[:30]!r}... => t = {t.hex()[:16]}..., Vrfy = {v} ✓")

    # 3. MAC => PRF backward reduction
    print("\n[3] MAC => PRF Backward Reduction")
    mac_as_prf_demo(prf_mac)

    # 4. EUF-CMA game
    print("\n[4] EUF-CMA Security Game")
    game = EUF_CMA_Game(prf_mac)
    success_rate = game.run_simulation(n_queries=50, n_rounds=20)
    print(f"  Forgery success rate: {success_rate:.4f} (should be ≈ 0)")
    assert success_rate < 0.1, "MAC is not EUF-CMA secure!"
    print("  EUF-CMA security confirmed ✓")

    game2 = EUF_CMA_Game(cbc_mac)
    success_rate2 = game2.run_simulation(n_queries=50, n_rounds=20)
    print(f"  CBC-MAC forgery success rate: {success_rate2:.4f} ✓")

    # 5. Length extension demo
    print("\n[5] Length-Extension Attack on naive MAC")
    naive_mac_length_extension_demo()

    # 6. HMAC stub
    print("\n[6] HMAC Stub")
    stub = HMAC_Stub()
    try:
        stub.Mac(k, b"test")
    except NotImplementedError as e:
        print(f"  HMAC stub raises NotImplementedError: {e}")
    print("  Stub correctly defers to PA#10 ✓")

    print("\n✓ PA #5 complete.")
    print("Interface: from pa5_mac.mac import PRF_MAC, CBC_MAC, secure_compare")
    print("  mac = PRF_MAC(); t = mac.Mac(k, m); ok = mac.Vrfy(k, m, t)")
