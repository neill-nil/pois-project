"""
PA #4 — Modes of Operation
CS8.401: Principles of Information Security

Implements:
1. CBC (Cipher Block Chaining)
2. OFB (Output Feedback)
3. Randomized CTR (Counter Mode)
4. Unified API: Encrypt(mode, k, M), Decrypt(mode, k, C)
5. Attack demos: CBC IV-reuse, OFB keystream-reuse
6. Correctness tests
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa2_prf'))
from prf import AES_PRF, aes_encrypt_block, aes_decrypt_block

BLOCK = 16


# ─────────────────────────────────────────────
# Padding
# ─────────────────────────────────────────────
def pkcs7_pad(data: bytes, block_size: int = BLOCK) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len == 0 or pad_len > BLOCK or data[-pad_len:] != bytes([pad_len]*pad_len):
        raise ValueError("Invalid padding")
    return data[:-pad_len]

def xor_blocks(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def block_increment(b: bytes) -> bytes:
    n = int.from_bytes(b, 'big') + 1
    return (n % (2 ** 128)).to_bytes(BLOCK, 'big')


# ─────────────────────────────────────────────
# CBC Mode
# ─────────────────────────────────────────────
class CBC:
    """
    Cipher Block Chaining:
    C_i = E_k(C_{i-1} XOR M_i),  C_0 = IV
    Decryption: M_i = D_k(C_i) XOR C_{i-1}
    
    Properties:
    - Sequential encryption, parallel decryption
    - 2-block error propagation
    - Requires random IV per message
    """
    def __init__(self):
        pass  # Uses raw AES block cipher

    def encrypt(self, k: bytes, m: bytes, iv: bytes = None) -> tuple:
        """Encrypt m; returns (iv, ciphertext)."""
        assert len(k) == BLOCK
        iv = iv or os.urandom(BLOCK)
        assert len(iv) == BLOCK
        padded = pkcs7_pad(m)
        n_blocks = len(padded) // BLOCK
        ct_blocks = []
        prev = iv
        for i in range(n_blocks):
            mi = padded[i*BLOCK:(i+1)*BLOCK]
            ci = aes_encrypt_block(xor_blocks(prev, mi), k)
            ct_blocks.append(ci)
            prev = ci
        return iv, b''.join(ct_blocks)

    def decrypt(self, k: bytes, iv: bytes, c: bytes) -> bytes:
        """Decrypt ciphertext c with given iv."""
        assert len(k) == BLOCK and len(iv) == BLOCK
        if len(c) % BLOCK != 0:
            raise ValueError("Ciphertext must be multiple of block size")
        n_blocks = len(c) // BLOCK
        pt_blocks = []
        prev = iv
        for i in range(n_blocks):
            ci = c[i*BLOCK:(i+1)*BLOCK]
            mi = xor_blocks(aes_decrypt_block(ci, k), prev)
            pt_blocks.append(mi)
            prev = ci
        return pkcs7_unpad(b''.join(pt_blocks))

    def Enc(self, k, m, iv=None): return self.encrypt(k, m, iv)
    def Dec(self, k, iv, c): return self.decrypt(k, iv, c)


# ─────────────────────────────────────────────
# OFB Mode
# ─────────────────────────────────────────────
class OFB:
    """
    Output Feedback Mode:
    O_i = E_k(O_{i-1}),  O_0 = IV
    C_i = M_i XOR O_i
    
    Properties:
    - Keystream is independent of plaintext
    - Encryption = Decryption (same operation)
    - Pre-computable keystream
    - Bit-flip in ciphertext -> bit-flip in same plaintext position only
    """
    def __init__(self):
        pass

    def _keystream(self, k: bytes, iv: bytes, n_bytes: int) -> bytes:
        """Pre-compute keystream."""
        assert len(k) == BLOCK and len(iv) == BLOCK
        ks = b''
        state = iv
        while len(ks) < n_bytes:
            state = aes_encrypt_block(state, k)
            ks += state
        return ks[:n_bytes]

    def encrypt(self, k: bytes, m: bytes, iv: bytes = None) -> tuple:
        """Encrypt; returns (iv, ciphertext). Enc = Dec."""
        iv = iv or os.urandom(BLOCK)
        ks = self._keystream(k, iv, len(m))
        c = xor_blocks(m, ks)
        return iv, c

    def decrypt(self, k: bytes, iv: bytes, c: bytes) -> bytes:
        """Decrypt — identical to encryption."""
        ks = self._keystream(k, iv, len(c))
        return xor_blocks(c, ks)

    def Enc(self, k, m, iv=None): return self.encrypt(k, m, iv)
    def Dec(self, k, iv, c): return self.decrypt(k, iv, c)


# ─────────────────────────────────────────────
# CTR Mode
# ─────────────────────────────────────────────
class CTR:
    """
    Randomized Counter Mode:
    r <- random nonce
    C_i = M_i XOR F_k(r + i)
    
    Properties:
    - Fully parallelizable (both directions)
    - Random access decryption
    - No padding needed (stream cipher)
    - Nonce r must be unique per key
    """
    def __init__(self, prf=None):
        self.prf = prf or AES_PRF()

    def _keystream_block(self, k: bytes, r: bytes, i: int) -> bytes:
        """Generate keystream block i."""
        counter = ((int.from_bytes(r, 'big') + i) % (2 ** 128)).to_bytes(BLOCK, 'big')
        return self.prf.F(k, counter)

    def encrypt(self, k: bytes, m: bytes) -> tuple:
        """Encrypt m; returns (r, ciphertext). r sampled internally."""
        r = os.urandom(BLOCK)
        n_blocks = (len(m) + BLOCK - 1) // BLOCK
        ks = b''.join(self._keystream_block(k, r, i) for i in range(n_blocks))
        c = xor_blocks(m, ks[:len(m)])
        return r, c

    def decrypt(self, k: bytes, r: bytes, c: bytes) -> bytes:
        """Decrypt — identical structure to encryption."""
        n_blocks = (len(c) + BLOCK - 1) // BLOCK
        ks = b''.join(self._keystream_block(k, r, i) for i in range(n_blocks))
        return xor_blocks(c, ks[:len(c)])

    def Enc(self, k, m): return self.encrypt(k, m)
    def Dec(self, k, r, c): return self.decrypt(k, r, c)


# ─────────────────────────────────────────────
# Unified API
# ─────────────────────────────────────────────
_MODES = {
    'CBC': CBC(),
    'OFB': OFB(),
    'CTR': CTR(),
}

def Encrypt(mode: str, k: bytes, M: bytes) -> dict:
    """
    Unified encryption API.
    Returns dict with 'ciphertext' and mode-specific params.
    """
    mode = mode.upper()
    if mode == 'CBC':
        iv, c = _MODES['CBC'].Enc(k, M)
        return {'mode': 'CBC', 'iv': iv, 'ciphertext': c}
    elif mode == 'OFB':
        iv, c = _MODES['OFB'].Enc(k, M)
        return {'mode': 'OFB', 'iv': iv, 'ciphertext': c}
    elif mode == 'CTR':
        r, c = _MODES['CTR'].Enc(k, M)
        return {'mode': 'CTR', 'nonce': r, 'ciphertext': c}
    else:
        raise ValueError(f"Unknown mode: {mode}. Choose CBC, OFB, or CTR.")

def Decrypt(mode: str, k: bytes, ct_dict: dict) -> bytes:
    """Unified decryption API."""
    mode = mode.upper()
    c = ct_dict['ciphertext']
    if mode == 'CBC':
        return _MODES['CBC'].Dec(k, ct_dict['iv'], c)
    elif mode == 'OFB':
        return _MODES['OFB'].Dec(k, ct_dict['iv'], c)
    elif mode == 'CTR':
        return _MODES['CTR'].Dec(k, ct_dict['nonce'], c)
    else:
        raise ValueError(f"Unknown mode: {mode}")


# ─────────────────────────────────────────────
# Attack Demos
# ─────────────────────────────────────────────
def demo_cbc_iv_reuse():
    """
    CBC IV-Reuse Attack:
    If M_1 == M_1' (same block 1) and same IV,
    then C_1 = E_k(IV XOR M_1) == C_1' -> leaks that M_1 == M_1'.
    """
    print("\n  CBC IV-Reuse Attack:")
    cbc = CBC()
    k = os.urandom(BLOCK)
    iv = os.urandom(BLOCK)  # Same IV — catastrophic!

    m1 = b'Attack at dawn!!' + b'Retreat at dusk!!'  # 2 blocks
    m2 = b'Attack at dawn!!' + b'Advance at noon!!'  # same block 1

    _, c1 = cbc.Enc(k, m1, iv=iv)
    _, c2 = cbc.Enc(k, m2, iv=iv)

    # Block 1 of both ciphertexts
    c1_b0 = c1[:BLOCK]
    c2_b0 = c2[:BLOCK]
    print(f"    M1[0] = M2[0] = 'Attack at dawn!!'")
    print(f"    C1[0] = {c1_b0.hex()}")
    print(f"    C2[0] = {c2_b0.hex()}")
    print(f"    C1[0] == C2[0]: {c1_b0 == c2_b0} ← leaks identical plaintext blocks!")

    # Different blocks
    c1_b1 = c1[BLOCK:2*BLOCK]
    c2_b1 = c2[BLOCK:2*BLOCK]
    print(f"    C1[1] = {c1_b1.hex()}")
    print(f"    C2[1] = {c2_b1.hex()}")
    print(f"    C1[1] == C2[1]: {c1_b1 == c2_b1} (different blocks → different ciphertext)")


def demo_ofb_keystream_reuse():
    """
    OFB Keystream-Reuse Attack:
    C1 XOR C2 = M1 XOR M2 (keystream cancels).
    """
    print("\n  OFB Keystream-Reuse Attack:")
    ofb = OFB()
    k = os.urandom(BLOCK)
    iv = os.urandom(BLOCK)  # Same IV — catastrophic!

    m1 = b'Secret message!!'
    m2 = b'Another secret!!'

    _, c1 = ofb.Enc(k, m1, iv=iv)
    _, c2 = ofb.Enc(k, m2, iv=iv)

    xor_ct = xor_blocks(c1, c2)
    xor_pt = xor_blocks(m1, m2)

    print(f"    C1 XOR C2 = {xor_ct.hex()}")
    print(f"    M1 XOR M2 = {xor_pt.hex()}")
    print(f"    Match: {xor_ct == xor_pt} ← keystream reuse leaks XOR of plaintexts!")

    # Given M1, recover M2
    recovered = xor_blocks(xor_ct, m1)
    print(f"    Recovered M2 = {recovered} (given M1)")
    assert recovered == m2
    print("    Full plaintext recovery ✓")


# ─────────────────────────────────────────────
# Correctness Tests
# ─────────────────────────────────────────────
def correctness_tests():
    """Test all modes on messages of various lengths."""
    print("\n  Correctness Tests:")
    k = os.urandom(BLOCK)
    test_messages = [
        (b"Short", "shorter than one block"),
        (b"Exactly 16 bytes", "exactly one block"),
        (b"A" * 48, "multiple blocks"),
    ]

    for mode in ['CBC', 'OFB', 'CTR']:
        print(f"\n    Mode: {mode}")
        for m, desc in test_messages:
            ct = Encrypt(mode, k, m)
            recovered = Decrypt(mode, k, ct)
            ok = "✓" if recovered == m else "✗ ERROR"
            print(f"      {desc} ({len(m)} bytes): {ok}")
            assert recovered == m, f"Decryption failed for {mode} with {desc}"


# ─────────────────────────────────────────────
# Error Propagation Analysis
# ─────────────────────────────────────────────
def error_propagation_demo():
    """Show how a bit flip in ciphertext affects decryption per mode."""
    print("\n  Error Propagation Demo:")
    k = os.urandom(BLOCK)
    m = b'Block one here!!' + b'Block two here!!' + b'Block three!!!!!!'

    for mode in ['CBC', 'OFB', 'CTR']:
        ct = Encrypt(mode, k, m)
        c = bytearray(ct['ciphertext'])
        # Flip first bit of second ciphertext block
        c[BLOCK] ^= 0x01
        ct_flipped = dict(ct)
        ct_flipped['ciphertext'] = bytes(c)
        try:
            recovered = Decrypt(mode, k, ct_flipped)
            # Count corrupted blocks
            n_blocks = len(m) // BLOCK
            corrupted = []
            for i in range(n_blocks):
                orig = m[i*BLOCK:(i+1)*BLOCK]
                rec  = recovered[i*BLOCK:(i+1)*BLOCK] if i*BLOCK < len(recovered) else b''
                if orig != rec:
                    corrupted.append(i)
            print(f"    {mode}: blocks corrupted = {corrupted} (flipped bit in block 1)")
        except Exception as e:
            print(f"    {mode}: Decryption failed (padding error): {e}")


# ─────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("PA #4 — Modes of Operation")
    print("=" * 60)

    correctness_tests()
    demo_cbc_iv_reuse()
    demo_ofb_keystream_reuse()
    error_propagation_demo()

    print("\n[Comparison Table]")
    print("  Mode  | Parallel Enc | Parallel Dec | Random Access | Error Prop")
    print("  CBC   |     No       |     Yes      |     No        |  2 blocks")
    print("  OFB   |     No       |     No       |     No        |  Same pos")
    print("  CTR   |     Yes      |     Yes      |     Yes       |  Same pos")

    print("\n✓ PA #4 complete.")
    print("Interface: from pa4_modes.modes import Encrypt, Decrypt")
    print("  ct = Encrypt('CBC', k, m); m = Decrypt('CBC', k, ct)")
