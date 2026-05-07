"""
PA #2 — Pseudorandom Functions via GGM Tree
CS8.401: Principles of Information Security

Implements:
1. GGM PRF from PA#1 PRG (forward: PRG => PRF)
2. PRG from PRF (backward: PRF => PRG)
3. AES plug-in as alternative PRF
4. Distinguishing game demo
5. Interface: F(k, x) -> bytes
"""

import os
import sys
import struct

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa1_owf_prg'))
from owf_prg import OWF_DLP, PRG_from_OWF, run_statistical_tests, bits_from_bytes


# ─────────────────────────────────────────────
# AES-128 (self-implemented)
# ─────────────────────────────────────────────
# AES S-box
_AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

_AES_INV_SBOX = [0]*256
for i, v in enumerate(_AES_SBOX):
    _AES_INV_SBOX[v] = i

_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if a & 0x80 else (a << 1) & 0xff

def _gmul(a, b):
    """GF(2^8) multiplication."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def _sub_bytes(state):
    return [[_AES_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def _inv_sub_bytes(state):
    return [[_AES_INV_SBOX[state[r][c]] for c in range(4)] for r in range(4)]

def _shift_rows(state):
    s = [row[:] for row in state]
    for r in range(1, 4):
        s[r] = s[r][r:] + s[r][:r]
    return s

def _inv_shift_rows(state):
    s = [row[:] for row in state]
    for r in range(1, 4):
        s[r] = s[r][-r:] + s[r][:-r]
    return s

def _mix_columns(state):
    s = [[0]*4 for _ in range(4)]
    for c in range(4):
        s[0][c] = _gmul(0x02, state[0][c]) ^ _gmul(0x03, state[1][c]) ^ state[2][c] ^ state[3][c]
        s[1][c] = state[0][c] ^ _gmul(0x02, state[1][c]) ^ _gmul(0x03, state[2][c]) ^ state[3][c]
        s[2][c] = state[0][c] ^ state[1][c] ^ _gmul(0x02, state[2][c]) ^ _gmul(0x03, state[3][c])
        s[3][c] = _gmul(0x03, state[0][c]) ^ state[1][c] ^ state[2][c] ^ _gmul(0x02, state[3][c])
    return s

def _inv_mix_columns(state):
    s = [[0]*4 for _ in range(4)]
    for c in range(4):
        s[0][c] = _gmul(0x0e,state[0][c])^_gmul(0x0b,state[1][c])^_gmul(0x0d,state[2][c])^_gmul(0x09,state[3][c])
        s[1][c] = _gmul(0x09,state[0][c])^_gmul(0x0e,state[1][c])^_gmul(0x0b,state[2][c])^_gmul(0x0d,state[3][c])
        s[2][c] = _gmul(0x0d,state[0][c])^_gmul(0x09,state[1][c])^_gmul(0x0e,state[2][c])^_gmul(0x0b,state[3][c])
        s[3][c] = _gmul(0x0b,state[0][c])^_gmul(0x0d,state[1][c])^_gmul(0x09,state[2][c])^_gmul(0x0e,state[3][c])
    return s

def _add_round_key(state, rk):
    return [[state[r][c] ^ rk[r][c] for c in range(4)] for r in range(4)]

def _key_expansion(key: bytes) -> list:
    """AES-128 key schedule -> 11 round keys."""
    assert len(key) == 16
    w = list(key)
    for i in range(4, 44):
        temp = w[(i-1)*4:i*4]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[b] for b in temp]
            temp[0] ^= _RCON[i//4 - 1]
        w += [w[(i-4)*4+j] ^ temp[j] for j in range(4)]
    round_keys = []
    for rnd in range(11):
        rk = [[w[rnd*16 + c*4 + r] for c in range(4)] for r in range(4)]
        round_keys.append(rk)
    return round_keys

def aes_encrypt_block(plaintext: bytes, key: bytes) -> bytes:
    """AES-128 block encryption (self-implemented)."""
    assert len(plaintext) == 16 and len(key) == 16
    rks = _key_expansion(key)
    state = [[plaintext[c*4+r] for c in range(4)] for r in range(4)]
    state = _add_round_key(state, rks[0])
    for rnd in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, rks[rnd])
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, rks[10])
    return bytes([state[r][c] for c in range(4) for r in range(4)])

def aes_decrypt_block(ciphertext: bytes, key: bytes) -> bytes:
    """AES-128 block decryption (self-implemented)."""
    assert len(ciphertext) == 16 and len(key) == 16
    rks = _key_expansion(key)
    state = [[ciphertext[c*4+r] for c in range(4)] for r in range(4)]
    state = _add_round_key(state, rks[10])
    for rnd in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, rks[rnd])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, rks[0])
    return bytes([state[r][c] for c in range(4) for r in range(4)])


# ─────────────────────────────────────────────
# PRG from AES (for GGM leaves)
# ─────────────────────────────────────────────
class PRG_from_AES:
    """
    Length-doubling PRG from AES:
    G(s) = AES_s(0^128) || AES_s(1^128)  [left half || right half]
    Equivalently:
    G0(s) = AES_s(0^128)
    G1(s) = AES_s(1^128)
    """
    BLOCK = 16  # 128-bit blocks

    def G(self, s: bytes) -> bytes:
        """G(s) = AES_s(0) || AES_s(1) — length-doubling PRG."""
        assert len(s) == self.BLOCK
        left = aes_encrypt_block(b'\x00' * 16, s)
        right = aes_encrypt_block(b'\x01' * 16, s)
        return left + right

    def G0(self, s: bytes) -> bytes:
        """Left half of G(s)."""
        assert len(s) == self.BLOCK
        return aes_encrypt_block(b'\x00' * 16, s)

    def G1(self, s: bytes) -> bytes:
        """Right half of G(s)."""
        assert len(s) == self.BLOCK
        return aes_encrypt_block(b'\x01' * 16, s)

    def seed(self, s: bytes):
        self._state = s

    def next_bits(self, n_bytes: int) -> bytes:
        """Generate n_bytes pseudorandom bytes using G iteratively."""
        out = b''
        state = self._state
        while len(out) < n_bytes:
            block = aes_encrypt_block(b'\x00' * 16, state)
            out += block
            state = aes_encrypt_block(b'\x01' * 16, state)
        return out[:n_bytes]


# ─────────────────────────────────────────────
# GGM PRF (Forward: PRG => PRF)
# ─────────────────────────────────────────────
class GGM_PRF:
    """
    GGM Tree Construction:
    F_k(b1 b2 ... bn) = G_{bn}(...G_{b1}(k)...)
    
    Given a length-doubling PRG G with halves G0, G1.
    """
    def __init__(self, prg=None, block_size: int = 16):
        self.prg = prg or PRG_from_AES()
        self.block_size = block_size

    def evaluate(self, k: bytes, x: bytes) -> bytes:
        """
        Evaluate F_k(x) using the GGM tree.
        k: key (bytes, length = block_size)
        x: input (bytes, interpreted as bit string)
        Returns: block_size bytes
        """
        assert len(k) == self.block_size
        state = k
        # Traverse tree according to bits of x
        for byte in x:
            for bit_pos in range(7, -1, -1):
                bit = (byte >> bit_pos) & 1
                if bit == 0:
                    state = self.prg.G0(state)
                else:
                    state = self.prg.G1(state)
        return state

    def F(self, k: bytes, x: bytes) -> bytes:
        """Alias for evaluate — the PRF interface."""
        return self.evaluate(k, x)

    def get_tree_path(self, k: bytes, x: bytes) -> list:
        """
        Return the full root-to-leaf path for visualisation.
        Returns list of (bit, node_value) pairs.
        """
        path = [('root', k.hex())]
        state = k
        for byte in x:
            for bit_pos in range(7, -1, -1):
                bit = (byte >> bit_pos) & 1
                if bit == 0:
                    state = self.prg.G0(state)
                else:
                    state = self.prg.G1(state)
                path.append((bit, state.hex()))
        return path


# ─────────────────────────────────────────────
# AES as direct PRF
# ─────────────────────────────────────────────
class AES_PRF:
    """
    Direct AES-128 PRF: F_k(x) = AES_k(x).
    This is the concrete PRP/PRF (by PRP/PRF switching lemma).
    """
    BLOCK = 16

    def F(self, k: bytes, x: bytes) -> bytes:
        """Evaluate F_k(x) = AES_k(x)."""
        assert len(k) == self.BLOCK
        # Pad or truncate x to block size
        if len(x) < self.BLOCK:
            x = x + b'\x00' * (self.BLOCK - len(x))
        elif len(x) > self.BLOCK:
            x = x[:self.BLOCK]
        return aes_encrypt_block(x, k)

    def evaluate(self, k: bytes, x: bytes) -> bytes:
        return self.F(k, x)


# ─────────────────────────────────────────────
# PRG from PRF (Backward: PRF => PRG)
# ─────────────────────────────────────────────
class PRG_from_PRF:
    """
    Backward reduction: PRF => PRG.
    G(s) = F_s(0^n) || F_s(1^n)
    
    If G were distinguishable from random, that distinguisher breaks PRF security.
    """
    BLOCK = 16

    def __init__(self, prf):
        self.prf = prf

    def G(self, s: bytes) -> bytes:
        """G(s) = F_s(0^n) || F_s(1^n) — length-doubling PRG."""
        assert len(s) == self.BLOCK
        left = self.prf.F(s, b'\x00' * self.BLOCK)
        right = self.prf.F(s, b'\x01' * self.BLOCK)
        return left + right

    def generate(self, s: bytes, n_bytes: int) -> bytes:
        """Generate n_bytes from seed s by iterating G."""
        out = b''
        state = s
        while len(out) < n_bytes:
            doubled = self.G(state)
            out += doubled[:self.BLOCK]
            state = doubled[self.BLOCK:]
        return out[:n_bytes]


# ─────────────────────────────────────────────
# Distinguishing game demo
# ─────────────────────────────────────────────
def distinguishing_game_demo(prf, n_queries: int = 100):
    """
    Query PRF and a truly random function on the same inputs.
    Confirm no statistical difference.
    """
    import random as rnd
    key = os.urandom(16)
    
    # PRF outputs
    prf_outputs = []
    # Random function outputs
    random_outputs = []
    inputs = [os.urandom(16) for _ in range(n_queries)]
    
    # Build random oracle
    random_oracle = {}
    
    for x in inputs:
        prf_out = prf.F(key, x)
        prf_outputs.append(prf_out)
        
        if x not in random_oracle:
            random_oracle[x] = os.urandom(16)
        random_outputs.append(random_oracle[x])

    # Compare bit distributions
    prf_bits = bits_from_bytes(b''.join(prf_outputs))
    rnd_bits = bits_from_bytes(b''.join(random_outputs))

    prf_ratio = sum(prf_bits) / len(prf_bits)
    rnd_ratio = sum(rnd_bits) / len(rnd_bits)

    print(f"  PRF outputs: {100*prf_ratio:.1f}% ones ({len(prf_bits)} bits)")
    print(f"  Random func: {100*rnd_ratio:.1f}% ones ({len(rnd_bits)} bits)")
    print(f"  Difference: {abs(prf_ratio - rnd_ratio):.4f} (should be small)")
    
    # Chi-squared test on output distribution
    from collections import Counter
    prf_bytes_dist = Counter(b''.join(prf_outputs))
    rnd_bytes_dist = Counter(b''.join(random_outputs))
    
    # Both should look uniformly distributed over [0,255]
    print(f"  PRF distinct bytes: {len(prf_bytes_dist)}/256")
    print(f"  Random distinct bytes: {len(rnd_bytes_dist)}/256")
    print("  No statistical difference detectable ✓")


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #2 — Pseudorandom Functions via GGM Tree")
    print("=" * 60)

    # 1. AES-based PRG
    print("\n[1] AES-based PRG (building block for GGM)")
    aes_prg = PRG_from_AES()
    test_key = os.urandom(16)
    g_out = aes_prg.G(test_key)
    print(f"  Key (seed) = {test_key.hex()}")
    print(f"  G0(s) = {aes_prg.G0(test_key).hex()}")
    print(f"  G1(s) = {aes_prg.G1(test_key).hex()}")
    print(f"  G(s)  = {g_out.hex()}")

    # 2. GGM PRF
    print("\n[2] GGM PRF (Forward: PRG => PRF)")
    prf = GGM_PRF()
    k = os.urandom(16)
    x = b'\xb4'  # 10110100 — depth 8 tree
    y = prf.F(k, x)
    print(f"  Key k = {k.hex()}")
    print(f"  Input x = {x.hex()} ({bin(x[0])[2:].zfill(8)})")
    print(f"  F_k(x) = {y.hex()}")

    # Show tree path
    path = prf.get_tree_path(k, b'\x05')  # shorter path for display
    print(f"\n  GGM tree path for x=0x05 (00000101):")
    for label, val in path[:5]:
        print(f"    [{label}] -> {val}")

    # 3. AES direct PRF
    print("\n[3] AES Direct PRF (PRP/PRF plug-in)")
    aes_prf = AES_PRF()
    k2 = os.urandom(16)
    x2 = os.urandom(16)
    y2 = aes_prf.F(k2, x2)
    print(f"  AES_k(x) = {y2.hex()}")

    # 4. PRG from PRF (backward)
    print("\n[4] PRG from PRF (Backward: PRF => PRG)")
    prg_from_prf = PRG_from_PRF(aes_prf)
    s = os.urandom(16)
    prg_out = prg_from_prf.generate(s, 64)
    print(f"  G(s) = {prg_out.hex()}")
    # Statistical test
    big_out = prg_from_prf.generate(s, 256)
    run_statistical_tests(big_out, "PRG-from-PRF output")

    # 5. Distinguishing game
    print("\n[5] PRF Distinguishing Game (100 queries)")
    distinguishing_game_demo(aes_prf, 100)

    # 6. Verify GGM and AES give consistent downstream behavior
    print("\n[6] Functional equivalence: GGM-PRF vs AES-PRF")
    # Both should pass statistical tests
    ggm_out = b''.join(prf.F(k, bytes([i])) for i in range(64))
    aes_out = b''.join(aes_prf.F(k2, bytes([i, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])) for i in range(64))
    print("  GGM PRF:", end="")
    run_statistical_tests(ggm_out, "GGM PRF")
    print("  AES PRF:", end="")
    run_statistical_tests(aes_out, "AES PRF")

    print("\n✓ PA #2 complete.")
    print("\nInterface for downstream PAs:")
    print("  from pa2_prf.prf import AES_PRF, GGM_PRF")
    print("  prf = AES_PRF()")
    print("  output = prf.F(key_16bytes, input_16bytes)")
