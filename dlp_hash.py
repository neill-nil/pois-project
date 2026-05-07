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

from miller_rabin import mod_exp, gen_safe_prime, is_prime

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
    Use tiny parameters (q ≈ 2^16) so the birthday attack completes quickly.
    """
    print("\n  Collision Resistance Demo:")

    # For the full-size params, show the hardness
    print(f"  Full-size group order q = {params.q} ({params.q.bit_length()}-bit)")
    print(f"  Birthday bound: O(sqrt(q)) ≈ 2^{params.q.bit_length()//2} evaluations")
    print(f"  Infeasible to brute-force at this size — use toy params instead.")

    # Create tiny params (q ≈ 2^16) for birthday attack demo
    print(f"\n  Creating toy parameters (16-bit q) for birthday attack demo...")
    tiny = DLPHashParams(bits=18)  # Small enough for birthday attack
    comp = DLPCompress(tiny)
    expected_birthday = int(tiny.q ** 0.5)
    print(f"  Toy group order q = {tiny.q}, birthday bound ≈ {expected_birthday}")

    # Birthday attack: find (x,y) != (x',y') with h(x,y) = h(x',y')
    import random
    seen = {}
    count = 0
    collision = None
    while count < 10 * expected_birthday + 5000:
        x = random.randint(0, tiny.q - 1)
        y = random.randint(0, tiny.q - 1)
        cv = x.to_bytes(comp.cv_bytes, 'big')
        block = y.to_bytes(comp.cv_bytes, 'big')
        h = comp.compress(cv, block)  # Use cv (not iv) so x is actually used
        count += 1
        if h in seen:
            x_prev, y_prev = seen[h]
            if (x, y) != (x_prev, y_prev):
                collision = ((x, y), (x_prev, y_prev), h)
                break
        else:
            seen[h] = (x, y)

    if collision is None:
        print(f"  No collision found in {count} evaluations (unexpected)")
        return

    (x1, y1), (x2, y2), h_val = collision
    print(f"\n  Birthday collision found at {count} evaluations (expected ≈ {expected_birthday}):")
    print(f"    (x={x1}, y={y1}) and (x'={x2}, y'={y2})")
    print(f"    h(x,y) = h(x',y') = {h_val.hex()}")

    # Verify collision via re-computation
    h_check1 = comp.compress(x1.to_bytes(comp.cv_bytes, 'big'), y1.to_bytes(comp.cv_bytes, 'big'))
    h_check2 = comp.compress(x2.to_bytes(comp.cv_bytes, 'big'), y2.to_bytes(comp.cv_bytes, 'big'))
    assert h_check1 == h_check2, "Collision verification failed!"
    print(f"    Collision verified: compress recomputed and matched ✓")

    # Show that a collision would solve DLP
    # g^x1 * h_hat^y1 = g^x2 * h_hat^y2
    # => g^(x1-x2) = h_hat^(y2-y1)
    # => log_g(h_hat) = (x1-x2) * (y2-y1)^(-1) mod q
    dy = (y2 - y1) % tiny.q
    dx = (x1 - x2) % tiny.q
    if dy != 0:
        dy_inv = pow(dy, tiny.q - 2, tiny.q)  # Fermat's little theorem
        alpha_recovered = (dx * dy_inv) % tiny.q
        # Verify: g^alpha should equal h_hat
        check = mod_exp(tiny.g, alpha_recovered, tiny.p)
        print(f"    DLP extraction: alpha = (x-x')/(y'-y) mod q = {alpha_recovered}")
        print(f"    Verify g^alpha mod p = {check}")
        print(f"    h_hat = {tiny.h_hat}")
        print(f"    g^alpha == h_hat: {check == tiny.h_hat} ← collision solves DLP! ✓")
    else:
        print(f"    y == y' but x != x' — trivial collision (same y, different x)")


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
