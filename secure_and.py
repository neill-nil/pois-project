"""
PA #19 — Secure AND Gate (and Secure XOR, NOT)
CS8.401: Principles of Information Security

Implements:
1. Secure AND(a, b) from PA#18 OT (1-of-2 OT as subroutine)
2. Secure XOR(a, b) — free via additive secret sharing over Z_2
3. Secure NOT(a)    — free via local bit flip
4. Privacy arguments (in code comments and demo)
5. Truth table verification for all four (a, b) combinations

Protocol for Secure AND:
  Alice has bit a, Bob has bit b. Goal: both learn a AND b.
  1. Alice acts as OT Sender with messages (m_0, m_1) = (0, a)
  2. Bob  acts as OT Receiver with choice bit b
  3. Bob  receives m_b = b * a = a AND b
  Both output a AND b.

  Privacy:
    - Bob learns only a AND b (not a alone), because OT hides m_{1-b}.
    - Alice learns nothing about b, because OT sender learns nothing about choice.

Secure XOR Protocol (additive secret sharing):
  1. Alice samples r <- {0,1} uniformly at random.
  2. Alice's share = a XOR r; Bob's share = b XOR r.
  3. Output = (a XOR r) XOR (b XOR r) = a XOR b.
  (r masks both inputs; neither party learns the other's bit.)

Secure NOT: Alice locally flips her share. No communication needed.

Dependencies: PA#18 (ot.py)
"""

import os
import sys
import random
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pa18_ot'))

from ot import OTParams, OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2


# ---------------------------------------------------------------------------
# Module-level shared OT parameters (initialised once for efficiency)
# ---------------------------------------------------------------------------

_ot_params = None

def _get_ot_params(bits: int = 128) -> OTParams:
    global _ot_params
    if _ot_params is None:
        _ot_params = OTParams(bits)
    return _ot_params


# ---------------------------------------------------------------------------
# Secure AND from OT
# ---------------------------------------------------------------------------

def Secure_AND(a: int, b: int, ot_params: OTParams = None, verbose: bool = False) -> int:
    """
    Secure AND gate using PA#18 OT as subroutine.

    Parties: Alice (has bit a), Bob (has bit b).
    Goal: both learn a AND b; neither learns the other's input.

    Protocol:
      Alice (OT Sender):   messages = (m_0=0, m_1=a)
      Bob   (OT Receiver): choice bit = b
      Bob receives m_b = 0 if b=0, or a if b=1  =>  m_b = a AND b

    Security argument:
      - Bob learns m_b = a AND b.
        For b=0: m_b=0 regardless of a, so Bob learns nothing about a.
        For b=1: m_b=a, so Bob learns a. But the AND function's output IS a in this case.
        Bob never learns a when a AND b would not reveal it.
        Formally: Bob's view is simulatable from b and the output (a AND b).
      - Alice learns nothing about b: OT sender privacy guarantees Alice sees only
        the two ciphertexts she created, which are computationally indistinguishable
        regardless of Bob's choice bit b.

    Returns: a AND b (integer 0 or 1)
    """
    assert a in (0, 1) and b in (0, 1), "Inputs must be bits (0 or 1)"
    if ot_params is None:
        ot_params = _get_ot_params()

    p = ot_params.p

    # Alice's OT messages: (m_0, m_1) = (0, a)
    # These are group elements; we encode bits as 1 and g (avoiding zero)
    # Use 1 to represent bit 0, and g to represent bit 1 (invertible encoding)
    g = ot_params.g
    m_0_grp = 1          # encodes bit 0
    m_1_grp = g          # encodes bit 1 (g^1 as representative)

    # Map Alice's bit a to group element
    # m_0 (OT message for b=0) = 0 (always)
    # m_1 (OT message for b=1) = a
    # Encoding: 0 -> 1 (group identity-like), 1 -> g
    def bit_to_group(bit: int) -> int:
        return 1 if bit == 0 else g

    def group_to_bit(elem: int) -> int:
        return 0 if elem == 1 else 1

    m_0_enc = bit_to_group(0)   # always 0
    m_1_enc = bit_to_group(a)   # a

    if verbose:
        print(f"    [AND] Alice's OT messages: m_0=0, m_1={a}  (as group: {m_0_enc}, {m_1_enc})")
        print(f"    [AND] Bob's choice bit: b={b}")

    # Bob runs OT Receiver Step 1
    pk_0, pk_1, state = OT_Receiver_Step1(ot_params, b)

    # Alice runs OT Sender Step
    C_0, C_1 = OT_Sender_Step(ot_params, pk_0, pk_1, m_0_enc, m_1_enc)

    # Bob runs OT Receiver Step 2
    m_b_enc = OT_Receiver_Step2(state, C_0, C_1)
    result = group_to_bit(m_b_enc)

    if verbose:
        print(f"    [AND] Bob received m_b = {result}")

    # Both parties output the result
    expected = a & b
    assert result == expected, f"Secure AND incorrect: a={a}, b={b}, got={result}, expected={expected}"
    return result


# ---------------------------------------------------------------------------
# Secure XOR (free — additive secret sharing over Z_2)
# ---------------------------------------------------------------------------

def Secure_XOR(a: int, b: int, verbose: bool = False) -> int:
    """
    Secure XOR gate via additive secret sharing over Z_2.
    No OT needed — this is 'free' in the GMW model.

    Protocol:
      1. Alice samples r <- {0, 1} uniformly at random.
      2. Alice sends her share s_A = a XOR r to a 'combine' step.
         Bob holds s_B = b XOR r.
      3. Output = s_A XOR s_B = (a XOR r) XOR (b XOR r) = a XOR b.

    Implemented here as a single function (in real MPC, parties run separately).
    Privacy: r masks Alice's bit a from Bob, and masks Bob's bit b from Alice.
    """
    assert a in (0, 1) and b in (0, 1)
    r = random.randint(0, 1)
    share_alice = a ^ r   # Alice's masked share
    share_bob   = b ^ r   # Bob's masked share (in real MPC, only Bob computes this)
    result = share_alice ^ share_bob

    if verbose:
        print(f"    [XOR] r={r}, share_A={share_alice}, share_B={share_bob}, result={result}")

    assert result == (a ^ b)
    return result


# ---------------------------------------------------------------------------
# Secure NOT (free — local operation, no communication)
# ---------------------------------------------------------------------------

def Secure_NOT(a: int) -> int:
    """
    Secure NOT gate — free (local operation, no communication needed).
    Alice simply flips her share: NOT a = 1 - a = a XOR 1.
    """
    assert a in (0, 1)
    return 1 - a


# ---------------------------------------------------------------------------
# Truth Table Verification
# ---------------------------------------------------------------------------

def verify_truth_tables(ot_params: OTParams = None, trials_per_input: int = 50):
    """
    Verify AND and XOR truth tables across all four input combinations.
    Each (a, b) pair is tested trials_per_input times.
    """
    print(f"\n=== Truth Table Verification ({trials_per_input} trials per input) ===")
    if ot_params is None:
        ot_params = _get_ot_params()

    and_table = {(0,0): 0, (0,1): 0, (1,0): 0, (1,1): 1}
    xor_table = {(0,0): 0, (0,1): 1, (1,0): 1, (1,1): 0}

    and_errors = 0
    xor_errors = 0

    for a in range(2):
        for b in range(2):
            for _ in range(trials_per_input):
                res_and = Secure_AND(a, b, ot_params)
                res_xor = Secure_XOR(a, b)
                if res_and != and_table[(a, b)]:
                    and_errors += 1
                if res_xor != xor_table[(a, b)]:
                    xor_errors += 1

    print(f"  AND errors: {and_errors}/{4 * trials_per_input}")
    print(f"  XOR errors: {xor_errors}/{4 * trials_per_input}")

    print("\n  AND truth table:")
    for a in range(2):
        for b in range(2):
            out = Secure_AND(a, b, ot_params)
            expected = and_table[(a, b)]
            status = "✓" if out == expected else "✗"
            print(f"    AND({a},{b}) = {out}  (expected {expected}) {status}")

    print("\n  XOR truth table:")
    for a in range(2):
        for b in range(2):
            out = Secure_XOR(a, b)
            expected = xor_table[(a, b)]
            status = "✓" if out == expected else "✗"
            print(f"    XOR({a},{b}) = {out}  (expected {expected}) {status}")

    print("\n  NOT:")
    for a in range(2):
        out = Secure_NOT(a)
        print(f"    NOT({a}) = {out}  (expected {1-a}) {'✓' if out == 1-a else '✗'}")

    return and_errors == 0 and xor_errors == 0


# ---------------------------------------------------------------------------
# Privacy Analysis Demo
# ---------------------------------------------------------------------------

def demo_privacy(ot_params: OTParams = None, num_transcripts: int = 10):
    """
    Generate protocol transcripts for AND(1, b) for b in {0,1}.
    Show that the transcript (messages exchanged) does not reveal the other's input.
    """
    print(f"\n=== Privacy Demo: AND(a=1, b=?) ===")
    if ot_params is None:
        ot_params = _get_ot_params()

    print("  Transcripts for b=0:")
    for _ in range(3):
        pk_0, pk_1, state = OT_Receiver_Step1(ot_params, 0)
        C_0, C_1 = OT_Sender_Step(ot_params, pk_0, pk_1,
                                   1,         # m_0 = 0 (bit) -> 1 (group)
                                   ot_params.g)  # m_1 = 1 (bit) -> g (group)
        print(f"    pk_0={pk_0 % 10**6}... pk_1={pk_1 % 10**6}... C_0={C_0[0] % 10**6}...")

    print("  Transcripts for b=1:")
    for _ in range(3):
        pk_0, pk_1, state = OT_Receiver_Step1(ot_params, 1)
        C_0, C_1 = OT_Sender_Step(ot_params, pk_0, pk_1,
                                   1, ot_params.g)
        print(f"    pk_0={pk_0 % 10**6}... pk_1={pk_1 % 10**6}... C_0={C_0[0] % 10**6}...")

    print("  Alice cannot distinguish b=0 from b=1 by inspecting the transcript.")
    print("  Both show two valid-looking public keys and two ciphertexts.")


# ---------------------------------------------------------------------------
# Public Interface for PA#20
# ---------------------------------------------------------------------------

def AND(a: int, b: int, ot_params: OTParams = None) -> int:
    """Public interface: AND(a, b) -> bit"""
    return Secure_AND(a, b, ot_params)


def XOR(a: int, b: int) -> int:
    """Public interface: XOR(a, b) -> bit"""
    return Secure_XOR(a, b)


def NOT(a: int) -> int:
    """Public interface: NOT(a) -> bit"""
    return Secure_NOT(a)


# ---------------------------------------------------------------------------
# Self-test / demonstration
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 65)
    print("PA #19 — Secure AND Gate (and XOR, NOT)")
    print("=" * 65)

    print("\n[1] Initialising OT parameters (128-bit)...")
    t0 = time.time()
    params = _get_ot_params(bits=128)
    print(f"    Done in {time.time()-t0:.3f}s")

    print("\n[2] Single AND gate tests...")
    for a in range(2):
        for b in range(2):
            result = AND(a, b, params)
            expected = a & b
            status = "✓" if result == expected else "✗"
            print(f"    AND({a},{b}) = {result}  {status}")

    print("\n[3] Single XOR gate tests...")
    for a in range(2):
        for b in range(2):
            result = XOR(a, b)
            expected = a ^ b
            status = "✓" if result == expected else "✗"
            print(f"    XOR({a},{b}) = {result}  {status}")

    print("\n[4] NOT gate tests...")
    for a in range(2):
        result = NOT(a)
        print(f"    NOT({a}) = {result}  {'✓' if result == 1-a else '✗'}")

    print("\n[5] Truth table verification (10 trials per input)...")
    ok = verify_truth_tables(params, trials_per_input=10)
    print(f"    All truth tables correct: {ok}")
    assert ok

    print("\n[6] Privacy demo...")
    demo_privacy(params)

    print("\n[7] Verbose AND trace (a=1, b=1)...")
    result = Secure_AND(1, 1, params, verbose=True)
    print(f"    AND(1,1) = {result}  (expected 1)")

    print("\n" + "=" * 65)
    print("All PA#19 tests passed.")
    print("=" * 65)
