# Viva Preparation Guide: POIS Assignments 13–16

This document is a comprehensive study guide for the Principles of Information Security viva voce covering Assignments 13 through 16:
- **PA #13**: Miller-Rabin Primality Testing
- **PA #14**: Chinese Remainder Theorem & Håstad’s Broadcast Attack
- **PA #15**: Digital Signatures (RSA Hash-then-Sign & Schnorr)
- **PA #16**: ElGamal Public-Key Cryptosystem

All code implementations correctly meet the assignment requirements, as verified by the test suites and cross-referenced with the assignment specifications.

---

## 1. PA #13: Miller-Rabin Primality Testing

### Core Concepts
*   **Why not deterministic tests?** Deterministic primality tests like AKS exist but are too slow (polynomial time but with a high constant). Miller-Rabin is probabilistic, extremely fast, and its error probability can be made negligible.
*   **Why not Fermat's test?** Fermat's Little Theorem ($a^{n-1} \equiv 1 \pmod n$) is fooled by **Carmichael numbers** (like 561). They are composite but satisfy the congruence for all $a$ coprime to $n$.
*   **The Miller-Rabin Logic:**
    1.  Factor $n-1 = 2^s \cdot d$ (where $d$ is odd).
    2.  For a random base $a$, consider the sequence: $a^d, a^{2d}, a^{4d}, \dots, a^{2^sd} \pmod n$.
    3.  If $n$ is prime, the sequence must either start with 1, or contain a -1 (which is $n-1$) before the first 1 appears.
    4.  If neither condition holds, $a$ is a "witness" for the compositeness of $n$.

### Implementation Details (`miller_rabin.py`)
*   **`mod_exp`**: Uses the square-and-multiply algorithm to efficiently compute modular exponentiations without creating massively huge intermediate numbers.
*   **`miller_rabin(n, k)`**: Runs $k$ rounds. An error only occurs if a composite number is declared prime. The probability of this is $\le 4^{-k}$. For $k=40$, error rate is $4^{-40} = 2^{-80}$, which is cryptographically negligible.
*   **`gen_prime(bits)`**: Generates a random odd number of `bits` length, sets the most significant bit (to ensure it's exactly the right size), and tests it using `miller_rabin`.
*   **`gen_safe_prime(bits)`**: Generates primes $p$ and $q$ such that $p = 2q + 1$. Used for creating groups where the Discrete Logarithm Problem (DLP) is hard, preventing attacks like Pohlig-Hellman.

### Potential Viva Questions
> **Q: How does the Miller-Rabin test handle Carmichael numbers?**
> A: While Carmichael numbers pass $a^{n-1} \equiv 1 \pmod n$, Miller-Rabin goes further. It looks at the sequence of square roots of 1 modulo $n$. In $\mathbb{Z}_n$ where $n$ is prime, the only square roots of 1 are 1 and -1. If Miller-Rabin finds a non-trivial square root of 1, it knows $n$ is composite. This catches Carmichael numbers.
>
> **Q: What is the time complexity of generating an $N$-bit prime?**
> A: By the Prime Number Theorem, the density of primes around $x$ is $1 / \ln(x)$. For an $N$-bit number, we need to test approximately $\ln(2^N) = N \ln(2) \approx 0.69N$ candidates on average. Each Miller-Rabin test takes $O(k \cdot N^3)$ time (due to modular exponentiations).
>
> **Q: Why do we generate "safe primes" for DH/ElGamal?**
> A: We need the group size (order) to have a large prime factor to resist the Pohlig-Hellman algorithm, which solves DLP efficiently if the group order is smooth (made of small prime factors). A safe prime $p=2q+1$ ensures the subgroup of order $q$ is secure.

---

## 2. PA #14: Chinese Remainder Theorem & Textbook RSA Attacks

### Core Concepts
*   **CRT as an Optimizer (Garner's Algorithm):** Instead of calculating $c^d \pmod{pq}$, we compute $m_p = c^{d_p} \pmod p$ and $m_q = c^{d_q} \pmod q$, then combine them. Since exponentiation takes cubic time, doing two half-size exponentiations is about 4x faster ($2 \times (1/2)^3 = 1/4$).
*   **CRT as a Weapon (Håstad's Broadcast Attack):** If Alice sends the same message $m$ to 3 people using $e=3$ and different moduli $N_1, N_2, N_3$, Eve intercepts $c_1, c_2, c_3$. By CRT, Eve finds $x = m^3 \pmod{N_1 N_2 N_3}$. Because $m < N_i$, $m^3 < N_1 N_2 N_3$. Thus, no modular reduction actually happened on the combined value. Eve simply takes the regular integer cube root of $x$ to find $m$.

### Implementation Details (`crt.py`)
*   **`crt(residues, moduli)`**: Computes the unique solution $x \pmod{N}$ (where $N = \prod n_i$). It calculates $M_i = N/n_i$, then $x = \sum a_i M_i (M_i^{-1} \pmod{n_i}) \pmod N$.
*   **`rsa_dec_crt`**: Implements Garner's recombination: $h = q_{inv}(m_p - m_q) \pmod p$, then $m = m_q + h \cdot q$.
*   **`hastad_attack`**: Uses CRT to find $m^e$, then calls `integer_root` (implemented via Newton's method) to recover $m$.
*   **Padding Defense:** The script explicitly demonstrates that PKCS#1 v1.5 padding defeats Håstad's attack because the padding adds random bytes. Thus, Alice encrypts $m_{pad1}, m_{pad2}, m_{pad3}$, not just $m$. The CRT combination produces garbage since the "plaintexts" are no longer identical.

### Potential Viva Questions
> **Q: Explain how Garner's algorithm combines the partial results $m_p$ and $m_q$.**
> A: It calculates a coefficient $h = (m_p - m_q) \cdot q^{-1} \pmod p$. Then $m = m_q + h \cdot q$. This guarantees $m \equiv m_q \pmod q$ (since $h \cdot q$ is a multiple of $q$) and $m \equiv m_q + (m_p - m_q) \equiv m_p \pmod p$.
>
> **Q: Why does Håstad's attack fail if the message $m$ is larger than the moduli?**
> A: If $m$ was somehow larger than $N_i$ (which isn't allowed in standard RSA anyway), $m^e$ would be larger than $N_1 N_2 \dots N_e$. The CRT step yields $x = m^e \pmod{N_1 \dots N_e}$, which involves a wrap-around. The standard integer $e$-th root of $x$ would no longer yield $m$.
>
> **Q: How does PKCS#1 v1.5 prevent the broadcast attack?**
> A: PKCS#1 v1.5 prepends a string of random, non-zero bytes (at least 8 bytes) to the message. Even if the underlying message $m$ is the same, the padded messages $M_1, M_2, M_3$ are different with overwhelming probability. CRT requires identical messages across the congruences.

---

## 3. PA #15: Digital Signatures

### Core Concepts
*   **Hash-then-Sign Paradigm:** We never sign raw messages ($m^d \pmod N$). We sign the hash of the message ($H(m)^d \pmod N$). This prevents existential forgery (EUF-CMA).
*   **Multiplicative Homomorphism of Textbook RSA:** If you sign raw messages, $Sign(m_1) \cdot Sign(m_2) = m_1^d \cdot m_2^d = (m_1 m_2)^d \pmod N = Sign(m_1 \cdot m_2)$. An attacker who gets signatures for $m_1$ and $m_2$ can forge a signature for $m_1 \cdot m_2$ without the private key. Hashing destroys this homomorphic property because $H(m_1 \cdot m_2) \neq H(m_1) \cdot H(m_2)$.
*   **Schnorr Signatures (DLP-based):** An alternative to RSA. Uses a prime-order group. It relies on the Discrete Logarithm Problem. The signature is $(e, s)$ where $e = H(R \parallel m)$ and $s = r - x \cdot e \pmod q$.

### Implementation Details (`signatures.py`)
*   **`sign` and `verify`**: Uses the DLP hash from PA#8 to map the message to an integer $h \in [1, N-1]$. Then computes $h^d \pmod N$. Verification checks if $\sigma^e \pmod N == h$.
*   **`EUF_CMA_Game`**: Simulates the Existential Unforgeability under Chosen Message Attack game. The adversary queries the oracle but fails to forge a signature for a *new* message, proving the scheme's security.
*   **`multiplicative_forgery_attack`**: Exploits `raw_rsa_sign`. Computes $\sigma_{forged} = (\sigma_1 \cdot \sigma_2) \pmod N$ and verifies it against $m_1 \cdot m_2 \pmod N$. Then, it proves this fails when `Hash-then-Sign` is used.
*   **`SchnorrSignature`**: Generates a safe prime group. Implements the standard Schnorr signature generation and verification protocol.

### Potential Viva Questions
> **Q: Define the EUF-CMA security model for digital signatures.**
> A: Existential Unforgeability under Chosen Message Attacks. "Existential Unforgeability" means the attacker cannot create a valid signature for *any* message (even a garbage message). "Chosen Message Attack" means the attacker has access to an oracle that will sign any messages the attacker chooses, except the one they eventually forge.
>
> **Q: Why does the multiplicative forgery attack work on raw RSA?**
> A: Because textbook RSA is multiplicatively homomorphic. The signature function is just exponentiation by $d$. The product of two exponentiations is the exponentiation of the product: $m_1^d \cdot m_2^d \equiv (m_1 m_2)^d \pmod N$.
>
> **Q: Walk me through Schnorr verification.**
> A: The verifier receives $(e, s)$ and the message $m$. They compute $R' = g^s \cdot y^e \pmod p$. They then recompute the hash $e' = H(R' \parallel m)$. The signature is valid if $e' == e$. This works because $g^s \cdot y^e = g^{r - xe} \cdot (g^x)^e = g^{r - xe + xe} = g^r = R$.

---

## 4. PA #16: ElGamal Public-Key Cryptosystem

### Core Concepts
*   **DLP vs. DDH:** ElGamal security relies on the Decisional Diffie-Hellman (DDH) assumption, not just DLP. DLP says "given $g$ and $g^a$, finding $a$ is hard". DDH says "given $g^a, g^b$, it is hard to distinguish $g^{ab}$ from $g^c$ (a random group element)".
*   **ElGamal Encryption:** Requires a cyclic group. To encrypt $m$, pick random $r$. Ciphertext is $(c_1, c_2) = (g^r, m \cdot h^r) \pmod p$, where $h=g^x$ is the public key.
*   **ElGamal Decryption:** Compute $c_2 / c_1^x = (m \cdot g^{xr}) / (g^r)^x = m$.
*   **Malleability (CCA Insecurity):** Like textbook RSA, basic ElGamal is malleable. If you have $(c_1, c_2)$ encrypting $m$, you can create $(c_1, 2 \cdot c_2)$ which decrypts to $2m$. An active attacker with access to a decryption oracle (CCA attack) can use this to recover $m$.

### Implementation Details (`elgamal.py`)
*   **`ElGamalParams`**: Reuses the safe prime generation to create a subgroup of prime order $q$. This ensures the DDH assumption holds.
*   **`ElGamal_Enc`**: Generates a *fresh* random $r$ for every encryption. This randomized encryption is what provides IND-CPA security.
*   **`IND_CPA_Game_ElGamal`**: Simulates the IND-CPA game. The dummy adversary's advantage is ~0, showing indistinguishability.
*   **`malleability_attack_multiply`**: Takes $c_2$ and multiplies it by a factor. The decryption of $(c_1, c_2_{mod})$ is shown to be $factor \cdot m$, proving the scheme is not CCA-secure.
*   **`ddh_hardness_demo`**: Demonstrates that in a tiny 64-bit group, an attacker can brute-force the discrete log to distinguish a DDH tuple, breaking the encryption.

### Potential Viva Questions
> **Q: Why does ElGamal require the DDH assumption to be IND-CPA secure, rather than just DLP?**
> A: IND-CPA requires the ciphertext to look indistinguishable from random noise. The ciphertext is $(g^r, m \cdot h^r) = (g^r, m \cdot g^{xr})$. If an attacker provides $m_0, m_1$, they get $(g^r, m_b \cdot g^{xr})$. If DDH is false, the attacker can distinguish $(g^x, g^r, g^{xr})$ from a random tuple, allowing them to determine if $c_2$ is $m_0 \cdot g^{xr}$ or $m_1 \cdot g^{xr}$. If only DLP was hard, they couldn't recover the key, but they might still distinguish the ciphertexts.
>
> **Q: How does the ElGamal malleability attack prove it is not CCA-secure?**
> A: In a Chosen Ciphertext Attack (CCA) game, the attacker wants to decrypt a challenge ciphertext $C = (c_1, c_2)$ for message $m$. They cannot ask the oracle to decrypt $C$ directly. But they can ask the oracle to decrypt $C' = (c_1, 2 \cdot c_2 \pmod p)$. The oracle returns $2m$. The attacker computes $(2m) \cdot 2^{-1} \pmod p$ to recover $m$, winning the game.
>
> **Q: Why is ElGamal randomized, while textbook RSA is deterministic?**
> A: Textbook RSA uses $c = m^e \pmod N$. Encrypting $m$ always gives the same $c$. An attacker can just encrypt likely guesses and compare them to the ciphertext (breaking CPA security). ElGamal introduces a random ephemeral key $r$ for every encryption: $c_1 = g^r, c_2 = m \cdot h^r$. Encrypting the same message twice yields entirely different ciphertexts.
