"""
PA #18 — Oblivious Transfer (OT)
CS8.401: Principles of Information Security

Implements:
1. 1-out-of-2 Oblivious Transfer from PA#16 ElGamal PKC (Bellare-Micali style)
2. Three-step API:
   - OT_Receiver_Step1(b) -> (pk_0, pk_1, state)
   - OT_Sender_Step(pk_0, pk_1, m0, m1) -> (C_0, C_1)
   - OT_Receiver_Step2(state, C_0, C_1) -> m_b
3. Receiver privacy: sender cannot determine choice bit b
4. Sender privacy: receiver cannot decrypt the unchosen message
5. Correctness: receiver always gets m_b correctly

Lineage: PA#18 → PA#16 (ElGamal) → PA#11 (DH group) → PA#13 (Miller-Rabin)

OT Protocol (Bellare-Micali style over ElGamal group):
  Setup: Group (p, g, q) from PA#16. Public element h = g^alpha (alpha unknown).
  Receiver (choice b):
    - Generate honest key pair for chosen side: (r_b, pk_b = g^r_b)
    - For unchosen side: set pk_{1-b} = h / pk_b  (or random without DL)
      [Receiver knows DL of pk_b but not of pk_{1-b}]
  Sender:
    - Encrypt m_0 under pk_0: C_0 = ElGamal(pk_0, m_0)
    - Encrypt m_1 under pk_1: C_1 = ElGamal(pk_1, m_1)
  Receiver:
    - Decrypt C_b using r_b (knows DL of pk_b)
    - Cannot decrypt C_{1-b} (does not know DL of pk_{1-b})
"""

import os
import sys
import random
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa16_elgamal'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa13_miller_rabin'))

from Q16_elgamal import ElGamalParams, elgamal_keygen, ElGamal_Enc, ElGamal_Dec, Enc, Dec
from Q13_miller_rabin import mod_exp


# ---------------------------------------------------------------------------
# OT Parameters Setup
# ---------------------------------------------------------------------------

class OTParams:
    """
    Shared public parameters for OT.
    Holds an ElGamal group plus a public element h = g^alpha
    where alpha is discarded after setup (nobody knows the DL of h).

    This 'trapdoor element' h is needed for the Bellare-Micali trick:
    the receiver sets pk_{1-b} = h / pk_b so that pk_0 * pk_1 = h always.
    The sender can verify this consistency check.
    """

    def __init__(self, bits: int = 128):
        self.eg_params = ElGamalParams(bits)
        p, g, q = self.eg_params.p, self.eg_params.g, self.eg_params.q
        self.p = p
        self.g = g
        self.q = q
        # h = g^alpha for random alpha that is then discarded
        alpha = random.randint(1, q - 1)
        self.h = mod_exp(g, alpha, p)
        # alpha is intentionally forgotten here
        del alpha

    def random_message(self) -> int:
        """Return a random group element (valid plaintext for ElGamal)."""
        return self.eg_params.random_element()


# ---------------------------------------------------------------------------
# OT Receiver Step 1
# ---------------------------------------------------------------------------

def OT_Receiver_Step1(params: OTParams, b: int) -> tuple:
    """
    OT Receiver Step 1.
    Input: choice bit b in {0, 1}
    Output: (pk_0, pk_1, state)

    Construction:
      - For the chosen index b: generate honest DH key pair
          r_b <- Z_q,  pk_b = g^{r_b} mod p
      - For the unchosen index 1-b: compute
          pk_{1-b} = h * (pk_b)^{-1} mod p
        (receiver does NOT know the DL of pk_{1-b})

    This ensures pk_0 * pk_1 = h mod p always (consistency check for sender).
    The sender sees two public keys but cannot tell which one was generated honestly.

    state = (b, r_b, params) — kept private by receiver.
    """
    assert b in (0, 1), "Choice bit must be 0 or 1"
    p, g, q = params.p, params.g, params.q

    # Honest key for chosen side
    r_b = random.randint(1, q - 1)
    pk_b = mod_exp(g, r_b, p)

    # Key for unchosen side: pk_{1-b} = h / pk_b = h * pk_b^{-1} mod p
    pk_b_inv = pow(pk_b, -1, p)
    pk_1_minus_b = (params.h * pk_b_inv) % p

    if b == 0:
        pk_0, pk_1 = pk_b, pk_1_minus_b
    else:
        pk_0, pk_1 = pk_1_minus_b, pk_b

    state = {'b': b, 'r_b': r_b, 'params': params}
    return pk_0, pk_1, state


# ---------------------------------------------------------------------------
# OT Sender Step
# ---------------------------------------------------------------------------

def OT_Sender_Step(params: OTParams, pk_0: int, pk_1: int,
                   m0: int, m1: int) -> tuple:
    """
    OT Sender Step.
    Input: pk_0, pk_1 (receiver's public keys), m0, m1 (sender's two messages)
    Output: (C_0, C_1) where C_i = ElGamal_Enc under pk_i

    Optional consistency check: verify pk_0 * pk_1 == h mod p.
    If this fails, the receiver may have tampered with the keys.

    The sender encrypts BOTH messages and sends both ciphertexts.
    The sender learns nothing about b because both public keys look valid.
    """
    p, g, q = params.p, params.g, params.q

    # Optional: check pk_0 * pk_1 == h (receiver consistency)
    if (pk_0 * pk_1) % p != params.h:
        raise ValueError("OT protocol violation: pk_0 * pk_1 != h. Receiver cheated!")

    # Encrypt m0 under pk_0 using ElGamal
    # We must use pk_0 as the public key h component
    # Build a synthetic pk for ElGamal: (p, g, q, pk_0)
    synth_pk_0 = (p, g, q, pk_0)
    synth_pk_1 = (p, g, q, pk_1)

    C_0 = ElGamal_Enc(synth_pk_0, m0)
    C_1 = ElGamal_Enc(synth_pk_1, m1)

    return C_0, C_1


# ---------------------------------------------------------------------------
# OT Receiver Step 2
# ---------------------------------------------------------------------------

def OT_Receiver_Step2(state: dict, C_0: tuple, C_1: tuple) -> int:
    """
    OT Receiver Step 2.
    Input: state = {b, r_b, params}, C_0 = (c1_0, c2_0), C_1 = (c1_1, c2_1)
    Output: m_b (the chosen message)

    Decryption: C_b = (g^r, m_b * pk_b^r) mod p
    Using sk = r_b (DL of pk_b = g^{r_b}):
      Dec(r_b, c1, c2) = c2 / c1^{r_b} = m_b * pk_b^r / (g^r)^{r_b}
                       = m_b * g^{r_b * r} / g^{r * r_b} = m_b ✓

    The receiver CANNOT decrypt C_{1-b} because they don't know DL of pk_{1-b}.
    """
    b = state['b']
    r_b = state['r_b']
    params = state['params']
    p, g, q = params.p, params.g, params.q

    C_b = C_0 if b == 0 else C_1
    c1, c2 = C_b

    # Decrypt: m_b = c2 / c1^{r_b} mod p
    c1_rb = mod_exp(c1, r_b, p)
    c1_rb_inv = pow(c1_rb, -1, p)
    m_b = (c2 * c1_rb_inv) % p
    return m_b


# ---------------------------------------------------------------------------
# Privacy Demonstrations
# ---------------------------------------------------------------------------

def demo_receiver_privacy(params: OTParams, num_trials: int = 20):
    """
    Demonstrate that the sender cannot determine b from (pk_0, pk_1).

    From the sender's view: pk_0 and pk_1 are both valid group elements.
    pk_0 * pk_1 = h always holds regardless of b.
    Without knowing DLs, sender cannot distinguish which was generated honestly.

    Brute-force check for tiny group: try to find r such that g^r = pk_0 or pk_1.
    """
    print(f"\n=== Receiver Privacy Demo ({num_trials} trials) ===")
    p, g, q = params.p, params.g, params.q
    correct_guesses = 0

    for _ in range(num_trials):
        b = random.randint(0, 1)
        pk_0, pk_1, _ = OT_Receiver_Step1(params, b)

        # Sender attempts to guess b by brute-forcing DL of pk_0
        # (for toy parameters only — infeasible for large groups)
        max_search = min(q, 10000)
        found_r0 = False
        for r in range(1, max_search):
            if mod_exp(g, r, p) == pk_0:
                found_r0 = True
                break

        # If DL of pk_0 is found, sender guesses b=0 (receiver was honest with pk_0)
        # Otherwise, guesses b=1. But this is NOT reliable in practice.
        sender_guess = 0 if found_r0 else 1
        if sender_guess == b:
            correct_guesses += 1

    # For properly large groups, this should be ≈ 50% (random guessing)
    print(f"  Sender correct guesses: {correct_guesses}/{num_trials}")
    print(f"  (For large groups: ≈ 50%; brute-force is infeasible)")


def demo_sender_privacy(params: OTParams):
    """
    Demonstrate that receiver cannot decrypt the unchosen message.
    Attempts brute-force decryption of C_{1-b} for small parameters.
    """
    print("\n=== Sender Privacy Demo ===")
    p, g, q = params.p, params.g, params.q
    m0 = params.random_message()
    m1 = params.random_message()
    b = 0  # receiver wants m0
    print(f"  m0 = {m0}, m1 = {m1}, b = {b}")

    pk_0, pk_1, state = OT_Receiver_Step1(params, b)
    C_0, C_1 = OT_Sender_Step(params, pk_0, pk_1, m0, m1)

    # Receiver correctly decrypts m_b = m0
    m_b = OT_Receiver_Step2(state, C_0, C_1)
    print(f"  Receiver correctly decrypts m_{b} = {m_b} == m0? {m_b == m0}")
    assert m_b == m0

    # Receiver attempts to decrypt C_1 (the unchosen ciphertext)
    # They have r_b (DL of pk_b) but NOT the DL of pk_{1-b}
    # Brute-force for small q: attempt to find r such that g^r = pk_1
    c1_1, c2_1 = C_1
    r_b = state['r_b']
    print(f"  Attempting to decrypt C_1 without DL of pk_1...")

    # Try to find DL of pk_1 by exhaustive search
    max_search = min(q, 50000)
    found_r1 = None
    for r in range(1, max_search):
        if mod_exp(g, r, p) == pk_1:
            found_r1 = r
            break

    if found_r1 is not None:
        c1_r1 = mod_exp(c1_1, found_r1, p)
        m1_recovered = (c2_1 * pow(c1_r1, -1, p)) % p
        print(f"  [Small group] Brute-force found DL of pk_1: r={found_r1}, m1={m1_recovered}")
        print(f"  This is expected for tiny demo parameters!")
        print(f"  For 256+-bit groups, brute-force requires ~2^128 operations — infeasible.")
    else:
        print(f"  Could not find DL of pk_1 in {max_search} steps.")
        print(f"  Receiver cannot decrypt C_1 without the DL. ✓")


# ---------------------------------------------------------------------------
# Correctness Test
# ---------------------------------------------------------------------------

def correctness_test(params: OTParams, num_trials: int = 100):
    """Run 100 trials with random b and (m0, m1). Verify receiver always gets m_b."""
    print(f"\n=== OT Correctness Test ({num_trials} trials) ===")
    errors = 0
    for i in range(num_trials):
        b = random.randint(0, 1)
        m0 = params.random_message()
        m1 = params.random_message()

        pk_0, pk_1, state = OT_Receiver_Step1(params, b)
        C_0, C_1 = OT_Sender_Step(params, pk_0, pk_1, m0, m1)
        m_received = OT_Receiver_Step2(state, C_0, C_1)

        expected = m0 if b == 0 else m1
        if m_received != expected:
            errors += 1
            print(f"  ERROR at trial {i}: b={b}, expected={expected}, got={m_received}")

    print(f"  Errors: {errors}/{num_trials}")
    print(f"  Correctness: {'PASS' if errors == 0 else 'FAIL'}")
    return errors == 0


# ---------------------------------------------------------------------------
# Self-test / demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 65)
    print("PA #18 — Oblivious Transfer (OT)")
    print("=" * 65)

    print("\n[1] Setting up OT parameters (128-bit group)...")
    t0 = time.time()
    params = OTParams(bits=128)
    print(f"    p = {params.p}")
    print(f"    g = {params.g}")
    print(f"    h = {params.h}  (public trapdoor element, DL unknown)")
    print(f"    Setup time: {time.time()-t0:.3f}s")

    print("\n[2] Basic OT protocol (b=0, get m0)...")
    m0 = params.random_message()
    m1 = params.random_message()
    print(f"    m0 = {m0}, m1 = {m1}")

    pk_0, pk_1, state = OT_Receiver_Step1(params, b=0)
    print(f"    pk_0 = {pk_0}  (receiver honest key)")
    print(f"    pk_1 = {pk_1}  (trapdoor: no DL known)")
    print(f"    pk_0 * pk_1 mod p = h? {(pk_0 * pk_1) % params.p == params.h}")

    C_0, C_1 = OT_Sender_Step(params, pk_0, pk_1, m0, m1)
    print(f"    C_0 = {C_0}")
    print(f"    C_1 = {C_1}")

    m_received = OT_Receiver_Step2(state, C_0, C_1)
    print(f"    Received m_0 = {m_received}  (correct: {m_received == m0})")
    assert m_received == m0

    print("\n[3] OT protocol (b=1, get m1)...")
    pk_0b, pk_1b, state_b = OT_Receiver_Step1(params, b=1)
    C_0b, C_1b = OT_Sender_Step(params, pk_0b, pk_1b, m0, m1)
    m_received_1 = OT_Receiver_Step2(state_b, C_0b, C_1b)
    print(f"    Received m_1 = {m_received_1}  (correct: {m_received_1 == m1})")
    assert m_received_1 == m1

    print("\n[4] Correctness test (100 random trials)...")
    ok = correctness_test(params, num_trials=100)
    assert ok, "Correctness test failed!"

    print("\n[5] Sender privacy demo...")
    demo_sender_privacy(params)

    print("\n[6] Receiver privacy demo...")
    demo_receiver_privacy(params, num_trials=20)

    print("\n" + "=" * 65)
    print("All PA#18 tests passed.")
    print("=" * 65)
