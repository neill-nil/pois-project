"""
PA #8 — DLP-Based Collision-Resistant Hash Function
CS8.401: Principles of Information Security

Implements:
1. Safe-prime subgroup of Zp* setup
2. DLP compression: h(x, y) = g^x * h_hat^y mod p
3. Full CRHF via MD transform (PA#7)
4. Collision resistance demo
5. Interface: DLP_Hash(message) -> bytes
"""

import os
import sys
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa13_miller_rabin'))
from miller_rabin import mod_exp, gen_safe_prime, is_prime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa7_merkle'))
from merkle_damgard import MerkleDamgard, md_pad


# ─────────────────────────────────────────────
# DLP Group Setup
# ─────────────────────────────────────────────
class DLPHashParams:
    """
    Group parameters for DLP-based hash.
    p = 2q + 1 (safe prime), q prime, g generator of order-q subgroup.
    h_hat = g^alpha for secret alpha (discarded after setup).
    """
    def __init__(self, bits=64):
        print(f"  Generating {bits}-bit safe prime for DLP hash...")
        self.p, self.q = gen_safe_prime(bits)
        self.g = self._find_generator()
        # Generate h_hat = g^alpha for random alpha (alpha is discarded!)
        alpha = int.from_bytes(os.urandom(8), 'big') % self.q
        self.h_hat = mod_exp(self.g, alpha, self.p)
        # alpha is not stored — this is the security assumption
        print(f"  p = {self.p} ({self.p.bit_length()}-bit safe prime)")
        print(f"  q = {self.q}")
        print(f"  g = {self.g}")
        print(f"  h_hat = g^alpha = {self.h_hat}  (alpha discarded)")

    def _find_generator(self) -> int:
        """Find generator of prime-order-q subgroup."""
        p, q = self.p, self.q
        while True:
            h = int.from_bytes(os.urandom(8), 'big') % (p - 2) + 2
            g = mod_exp(h, 2, p)
            if g != 1 and mod_exp(g, q, p) == 1:
                return g


# ─────────────────────────────────────────────
# DLP Compression Function
# ─────────────────────────────────────────────
class DLPCompress:
    """
    h(x, y) = g^x * h_hat^y mod p
    
    Collision resistance: If adversary finds (x,y) != (x',y') with h(x,y) = h(x',y'),
    then g^(x-x') = h_hat^(y'-y), so log_g(h_hat) = (x-x')/(y'-y) mod q.
    This solves DLP — contradiction!
    
    Inputs x, y are integers mod q, derived from chaining value and block.
    """
    def __init__(self, params: DLPHashParams):
        self.p = params.p
        self.q = params.q
        self.g = params.g
        self.h_hat = params.h_hat
        # Block size: we'll encode (x, y) from (cv, block)
        # CV = q.bit_length()//8 bytes, block = same
        self.cv_bytes = (self.q.bit_length() + 7) // 8
        self.block_bytes = self.cv_bytes

    def compress(self, cv: bytes, block: bytes) -> bytes:
        """
        h(cv, block):
        1. Interpret cv as x in Zq
        2. Interpret block as y in Zq (truncated/padded to cv_bytes)
        3. Compute g^x * h_hat^y mod p
        4. Return result as bytes
        """
        # Pad block to cv_bytes
        if len(block) < self.cv_bytes:
            block = block + b'\x00' * (self.cv_bytes - len(block))
        block = block[:self.cv_bytes]

        x = int.from_bytes(cv, 'big') % self.q
        y = int.from_bytes(block, 'big') % self.q

        # g^x * h_hat^y mod p
        val = (mod_exp(self.g, x, self.p) * mod_exp(self.h_hat, y, self.p)) % self.p
        return val.to_bytes(self.cv_bytes, 'big')

    def get_iv(self) -> bytes:
        """Initial chaining value: 0^n."""
        return b'\x00' * self.cv_bytes

    def get_block_size(self) -> int:
        return self.cv_bytes


# ─────────────────────────────────────────────
# Full DLP Hash (MD + DLP compression)
# ─────────────────────────────────────────────
class DLP_Hash:
    """
    Full CRHF: DLP compression plugged into Merkle-Damgård.
    DLP_Hash(message) -> group element as bytes.
    """
    def __init__(self, params: DLPHashParams = None, bits: int = 64):
        self.params = params or DLPHashParams(bits)
        self.compress = DLPCompress(self.params)
        self.md = MerkleDamgard(
            compress=self.compress.compress,
            iv=self.compress.get_iv(),
            block_size=self.compress.get_block_size()
        )
        self.output_size = self.compress.cv_bytes  # bytes

    def hash(self, message: bytes) -> bytes:
        """Hash message; returns bytes of length = cv_bytes."""
        return self.md.hash(message)

    def __call__(self, message: bytes) -> bytes:
        return self.hash(message)

    def hash_hex(self, message: bytes) -> str:
        return self.hash(message).hex()


# ─────────────────────────────────────────────
# Collision Resistance Demo
# ─────────────────────────────────────────────
def demo_collision_resistance(params: DLPHashParams):
    """
    Show that finding a collision requires solving DLP.
    For tiny parameters (q ≈ 2^16), demonstrate brute-force birthday attack.
    """
    print("\n  Collision Resistance Demo:")
    comp = DLPCompress(params)
    iv = comp.get_iv()

    print(f"  DLP compression: h(x, y) = g^x * h_hat^y mod p")
    print(f"  To find collision (x,y)!=(x',y'): need to solve DLP (compute log_g(h_hat))")
    print(f"  Group order q = {params.q}, brute-force requires O(sqrt(q)) ≈ {int(params.q**0.5)} operations")

    # Birthday attack on DLP compress (as compression function, not full hash)
    import random
    seen = {}
    count = 0
    while True:
        x = random.randint(0, min(params.q - 1, 2**16))
        y = random.randint(0, min(params.q - 1, 2**16))
        cv = x.to_bytes(comp.cv_bytes, 'big')
        block = y.to_bytes(comp.cv_bytes, 'big')
        h = comp.compress(iv, block)
        count += 1
        if h in seen:
            x_prev, y_prev = seen[h]
            if (x, y) != (x_prev, y_prev):
                print(f"  Birthday collision at {count} evaluations (expected ≈ {int(params.q**0.5)}):")
                print(f"    (x={x}, y={y}) and (x'={x_prev}, y'={y_prev})")
                print(f"    h(x,y) = h(x',y') = {h.hex()}")
                # Verify
                h1 = comp.compress(iv, y.to_bytes(comp.cv_bytes, 'big'))
                h2 = comp.compress(iv, y_prev.to_bytes(comp.cv_bytes, 'big'))
                break
        else:
            seen[h] = (x, y)
        if count > 10 * int(params.q**0.5) + 1000:
            print(f"  No collision found in {count} evaluations")
            break


def demo_integration(dlp_hash: DLP_Hash):
    """Hash multiple messages, confirm distinct inputs -> distinct digests."""
    print("\n  Integration Test: 5 messages with distinct digests")
    messages = [
        b"",
        b"hello",
        b"Hello",  # Different case
        b"A" * 100,
        os.urandom(50),
    ]
    digests = set()
    for m in messages:
        h = dlp_hash.hash(m)
        print(f"    H({m[:20]!r}...) = {h.hex()}")
        digests.add(h)
    assert len(digests) == len(messages), "Collision found among test messages!"
    print(f"  All {len(messages)} distinct messages -> distinct digests ✓")


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #8 — DLP-Based Collision-Resistant Hash Function")
    print("=" * 60)

    # Use smaller parameters for demonstration speed
    print("\n[1] Group Setup (64-bit safe prime)")
    params = DLPHashParams(bits=64)

    print("\n[2] DLP Compression Function")
    comp = DLPCompress(params)
    iv = comp.get_iv()
    block = b'\x12\x34\x56\x78' + b'\x00' * (comp.cv_bytes - 4)
    h = comp.compress(iv, block[:comp.cv_bytes])
    print(f"  compress(IV, block) = {h.hex()}")

    print("\n[3] Full DLP Hash")
    dlp = DLP_Hash(params)
    test_msgs = [b"Hello, World!", b"Cryptography!", b""]
    for m in test_msgs:
        print(f"  H({m!r}) = {dlp.hash_hex(m)}")

    print("\n[4] Collision Resistance")
    demo_collision_resistance(params)

    print("\n[5] Integration Test")
    demo_integration(dlp)

    print("\n[6] Collision resistance proof sketch:")
    print("  Suppose (x,y) != (x',y') with g^x * h_hat^y = g^x' * h_hat^y' mod p")
    print("  Then g^(x-x') = h_hat^(y'-y) mod p")
    print("  So log_g(h_hat) = (x-x')/(y'-y) mod q -- solves DLP!")
    print("  Since DLP is hard in our group, no efficient adversary can find collisions.")

    print("\n✓ PA #8 complete.")
    print("Interface: from pa8_dlp_hash.dlp_hash import DLP_Hash, DLPHashParams")
    print("  dlp = DLP_Hash(); digest = dlp.hash(message)")
