"""
PA #7 — Merkle-Damgård Transform
CS8.401: Principles of Information Security

Implements:
1. Generic MerkleDamgard(compress, IV, block_size) framework
2. MD-strengthening padding
3. Toy XOR compression for testing
4. Collision propagation demo
5. Interface: hash(message, compression_fn) -> digest
"""

import os
import sys
import struct

BLOCK_BITS = 64      # Default block size in bits
OUTPUT_BITS = 32     # Default output size in bits


# ─────────────────────────────────────────────
# MD-Strengthening Padding
# ─────────────────────────────────────────────
def md_pad(message: bytes, block_size: int) -> bytes:
    """
    Merkle-Damgård strengthening padding:
    message || 0x80 || 0x00...00 || <64-bit length>
    such that total length is a multiple of block_size.
    
    block_size is in bytes.
    """
    msg_len_bits = len(message) * 8
    # Append 1 bit (0x80 byte)
    padded = message + b'\x80'
    # Append 0x00 bytes until: (len + 8) % block_size == 0
    # (need 8 bytes for the length field)
    while (len(padded) + 8) % block_size != 0:
        padded += b'\x00'
    # Append 64-bit big-endian length
    padded += struct.pack('>Q', msg_len_bits)
    assert len(padded) % block_size == 0
    return padded


# ─────────────────────────────────────────────
# Merkle-Damgård Framework
# ─────────────────────────────────────────────
class MerkleDamgard:
    """
    Generic Merkle-Damgård hash function.
    
    compress: function(chaining_value: bytes, block: bytes) -> bytes
              maps (n-bit state, b-bit block) -> n-bit state
    iv: initial value (bytes, same length as compress output)
    block_size: block size in bytes
    """
    def __init__(self, compress, iv: bytes, block_size: int):
        self.compress = compress
        self.iv = iv
        self.block_size = block_size

    def hash(self, message: bytes) -> bytes:
        """Compute MD hash of message."""
        # 1. Pad
        padded = md_pad(message, self.block_size)
        # 2. Parse into blocks
        n_blocks = len(padded) // self.block_size
        # 3. Process blocks
        z = self.iv
        for i in range(n_blocks):
            block = padded[i*self.block_size:(i+1)*self.block_size]
            z = self.compress(z, block)
        return z

    def hash_with_trace(self, message: bytes) -> list:
        """
        Hash with step-by-step trace for visualisation.
        Returns list of (block_hex, chaining_value_hex) per step.
        """
        padded = md_pad(message, self.block_size)
        n_blocks = len(padded) // self.block_size
        trace = [('IV', self.iv.hex())]
        z = self.iv
        for i in range(n_blocks):
            block = padded[i*self.block_size:(i+1)*self.block_size]
            z = self.compress(z, block)
            trace.append((f'M_{i+1}={block.hex()}', z.hex()))
        return trace


# ─────────────────────────────────────────────
# Toy Compression Function (XOR-based, for testing)
# ─────────────────────────────────────────────
def toy_compress_xor(cv: bytes, block: bytes) -> bytes:
    """
    Toy compression: h(cv, block) = XOR(cv, block_left) || XOR(cv, block_right)
    Extremely simple — not cryptographically secure! For testing only.
    
    cv: 4 bytes (chaining value)
    block: 8 bytes
    Returns: 4 bytes
    """
    assert len(cv) == 4 and len(block) == 8
    left = bytes(a ^ b for a, b in zip(cv, block[:4]))
    right = bytes(a ^ b for a, b in zip(cv, block[4:]))
    # Combine: XOR left and right, then add a non-linearity
    result = bytes((l ^ r + i) & 0xff for i, (l, r) in enumerate(zip(left, right)))
    return result


# ─────────────────────────────────────────────
# Toy Hash (using XOR compression via MD)
# ─────────────────────────────────────────────
class ToyHash(MerkleDamgard):
    """Toy hash using XOR compression, for testing PA#7."""
    BLOCK_SIZE = 8  # 8-byte blocks
    OUTPUT_SIZE = 4  # 4-byte output

    def __init__(self):
        iv = b'\x5a\xa5\x5a\xa5'  # Fixed IV
        super().__init__(toy_compress_xor, iv, self.BLOCK_SIZE)


# ─────────────────────────────────────────────
# Collision Propagation Demo
# ─────────────────────────────────────────────
def collision_propagation_demo():
    """
    Demonstrate: collision in compression function => collision in full hash.
    Find two inputs that collide under toy_compress_xor, then show they
    produce the same MD hash.
    """
    print("\n  Collision Propagation Demo:")
    toy = ToyHash()
    iv = toy.iv

    # Find a collision in toy_compress_xor for block starting from IV
    # Brute force: find two blocks b1 != b2 with compress(iv, b1) == compress(iv, b2)
    seen = {}
    collision = None
    for i in range(2**16):
        block = i.to_bytes(8, 'big')
        h = toy_compress_xor(iv, block)
        if h in seen:
            collision = (seen[h], block)
            break
        seen[h] = block

    if collision is None:
        print("    No collision found in search space (try more iterations)")
        return

    b1, b2 = collision
    assert b1 != b2
    assert toy_compress_xor(iv, b1) == toy_compress_xor(iv, b2)

    h1 = toy_compress_xor(iv, b1)
    print(f"    Compression collision found:")
    print(f"    b1 = {b1.hex()}, b2 = {b2.hex()}")
    print(f"    compress(IV, b1) = compress(IV, b2) = {h1.hex()}")

    # Both single-block messages collide under full MD hash
    # (pad to exactly one block)
    m1 = b1  # 8 bytes = exactly one block before padding
    m2 = b2

    full_h1 = toy.hash(m1)
    full_h2 = toy.hash(m2)
    print(f"\n    Full MD hash:")
    print(f"    H(m1={b1.hex()}) = {full_h1.hex()}")
    print(f"    H(m2={b2.hex()}) = {full_h2.hex()}")
    print(f"    H(m1) == H(m2): {full_h1 == full_h2}")
    print(f"    ↳ Collision in h propagates to full hash H ✓")


# ─────────────────────────────────────────────
# Convenience function: hash(message, compression_fn)
# ─────────────────────────────────────────────
def hash_message(message: bytes, compression_fn=None,
                 iv: bytes = None, block_size: int = 8) -> bytes:
    """
    Hash a message using MD transform with given compression function.
    Default: toy XOR compression.
    Interface for PA#8 to plug in DLP compression.
    """
    if compression_fn is None:
        compression_fn = toy_compress_xor
    if iv is None:
        output_len = 4  # Default: 4 bytes
        iv = b'\x5a\xa5\x5a\xa5'[:output_len]
    h = MerkleDamgard(compression_fn, iv, block_size)
    return h.hash(message)


# ─────────────────────────────────────────────
# Boundary Tests
# ─────────────────────────────────────────────
def boundary_tests():
    """Test: empty message, single-block message, multi-block message."""
    toy = ToyHash()
    test_cases = [
        (b'', "empty message"),
        (b'Hello!!', "7 bytes (< 1 block)"),
        (b'Exactly8', "exactly 8 bytes (= 1 block)"),
        (b'A' * 16, "16 bytes (2 blocks)"),
        (b'B' * 100, "100 bytes (multi-block)"),
    ]
    print("\n  Boundary Tests:")
    for msg, desc in test_cases:
        h = toy.hash(msg)
        print(f"    '{desc}' ({len(msg)} bytes): {h.hex()} ✓")

    # Distinct inputs should produce distinct digests (small sample for 4-byte hash)
    print("\n  Collision resistance (distinct inputs -> distinct digests):")
    hashes = {}
    for i in range(5):
        m = os.urandom(20)
        h = toy.hash(m)
        assert h not in hashes or hashes[h] == m, f"Collision found between {m.hex()} and {hashes[h].hex()}"
        hashes[h] = m
    print(f"    5 random messages: all distinct hashes ✓")


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #7 — Merkle-Damgård Transform")
    print("=" * 60)

    # 1. Padding demo
    print("\n[1] MD-Strengthening Padding")
    for msg_len in [0, 7, 8, 15, 16, 100]:
        msg = b'A' * msg_len
        padded = md_pad(msg, 8)
        print(f"  msg len={msg_len} bytes -> padded len={len(padded)} bytes, "
              f"n_blocks={len(padded)//8} ✓")
        assert len(padded) % 8 == 0

    # 2. Hash with trace
    print("\n[2] Hash with Step-by-Step Trace")
    toy = ToyHash()
    msg = b"Hello, World!"
    trace = toy.hash_with_trace(msg)
    print(f"  Message: {msg!r}")
    for label, val in trace:
        print(f"    {label[:30]}: z = {val}")

    # 3. Boundary tests
    boundary_tests()

    # 4. Collision propagation
    collision_propagation_demo()

    print("\n✓ PA #7 complete.")
    print("Interface: from pa7_merkle.merkle_damgard import MerkleDamgard, md_pad, hash_message")
    print("  h = MerkleDamgard(compress_fn, iv, block_size)")
    print("  digest = h.hash(message)")
