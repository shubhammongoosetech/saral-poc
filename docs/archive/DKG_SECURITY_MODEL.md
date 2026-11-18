# SARAL Protocol V3 — Dealerless DKG Security Model & Cryptographic Proofs

**Document Version:** 1.0.0  
**Phase:** Phase 3 — Dealerless Distributed Key Generation (DKG)  
**Status:** IMPLEMENTED & FORMALLY AUDITED  
**Research References:**
1. *“Distributed Key Generation in the Wild”* — Aniket Kate, Yizhou Huang, Ian Goldberg (ACM ASIACCS 2012 / ePrint 2012/377).
2. *“Asynchronous Verifiable Secret Sharing and Proactive Cryptosystems”* — Christian Cachin, Klaus Kursawe, Anna Lysyanskaya, Reto Strobl (ACM CCS 2002 / ePrint 2002/134).

---

## 1. Network & Adversary Model

The security model of SARAL Protocol V3's Dealerless Distributed Key Generation is grounded in the standard asynchronous Byzantine network model formalized by Canetti & Rabin (1993) and Kate et al. (2012):

1. **Adversary Bound ($t$):**
   An active Byzantine adversary $\mathcal{A}$ may corrupt up to $t$ out of $n$ participants.
   - For the Global Committee ($n=15$): $t = 4$, with threshold $k = 5$.
   - For the Domain Committee ($n=5$): $t = 1$, with threshold $k = 2$.
   - The corrupted nodes may deviate arbitrarily from the protocol: send conflicting shares, falsify commitments, drop or delay messages, collude, or crash.

2. **Asynchronous Network:**
   - Message transmission between honest nodes is eventually reliable but subjected to arbitrary, adversary-controlled delays.
   - No global clock, synchronous rounds, or synchronized timeouts are assumed.
   - The adversary cannot forge authenticated point-to-point links protected by Ed25519 signatures and TLS 1.3 mTLS channels.

3. **Cryptographic Assumptions:**
   - **Discrete Logarithm (DL) & Decisional Diffie-Hellman (DDH) Assumptions** hold over the prime-order subgroup of the NIST P-256 elliptic curve ($\mathbb{E}(\mathbb{F}_P)$ of order $N$).
   - **Random Oracle Model (ROM)** is assumed for Chaum-Pedersen Non-Interactive Zero-Knowledge (NIZK) proofs of discrete logarithm equality (DLEQ) and Verifiable Threshold Common Coins.

---

## 2. Core Security Properties

An asynchronous DKG protocol $\Pi_{\text{DKG}}$ must satisfy three foundational properties in the presence of $t$ Byzantine corruptions:

### Property 1: Correctness (Uniqueness of Master Public Key)
Except with negligible probability, all honest participants $P_j$ terminate with:
1. The exact same Qualified Set $QUAL^* \subseteq \{P_1, \dots, P_n\}$ where $|QUAL^*| \ge n - t$.
2. The exact same Master Public Key $Y \in \mathbb{E}(\mathbb{F}_P)$:
   $$Y = \sum_{i \in QUAL^*} C^{(i)}_{0, 0} = x \cdot G$$
3. Consistent private shares $x_j$ such that any subset $\mathcal{S}$ of $k$ honest nodes can uniquely reconstruct the master secret $x = \sum_{i \in QUAL^*} z_i \pmod N$ using Lagrange interpolation:
   $$x = \sum_{j \in \mathcal{S}} \lambda_j x_j \pmod N \quad \text{where } \lambda_j = \prod_{m \in \mathcal{S}, m \ne j} \frac{-m}{j - m} \pmod N$$
   and $x \cdot G = Y$.

### Property 2: Secrecy (Uniform Distribution & Unpredictability)
The joint distribution of the master private key $x$ is statistically indistinguishable from uniform over $\mathbb{Z}_N$, conditioned on the adversary's entire view during the protocol execution.
- **Proof intuition:**
  Let $\mathcal{H} = \{P_1, \dots, P_n\} \setminus \mathcal{A}$ denote the set of honest participants.
  Because $|QUAL^*| \ge n - t$ and $|\mathcal{A}| \le t$:
  $$|QUAL^* \cap \mathcal{H}| \ge (n - t) - t = n - 2t$$
  By the reconstruction bound $n - 2t \ge k \ge 1$:
  $$|QUAL^* \cap \mathcal{H}| \ge 1$$
  Specifically, for $n=15, t=4$:
  $$|QUAL^* \cap \mathcal{H}| \ge 11 - 4 = 7 \text{ honest contributors.}$$
  The master private key is $x = \sum_{i \in QUAL^*} z_i \pmod N = \sum_{i \in QUAL^* \cap \mathcal{A}} z_i + \sum_{i \in QUAL^* \cap \mathcal{H}} z_i \pmod N$.
  Since each honest $P_i \in \mathcal{H}$ independently samples $z_i \in_R \mathbb{Z}_N$ from a cryptographically secure random source (`crypto/rand`), and information-theoretically hides $z_i$ behind Pedersen commitments $C^{(i)}_{m, \ell} = A_{m, \ell} G + B_{m, \ell} H$, the adversary has zero information regarding $\sum_{i \in QUAL^* \cap \mathcal{H}} z_i \pmod N$. Thus, $x$ has full 256-bit min-entropy.

### Property 3: Liveness & Termination
In an asynchronous network, any protocol that requires all $n$ nodes to contribute can be permanently blocked by an adversary delaying even a single corrupted node $t \ge 1$.
- SARAL Protocol V3 solves this by requiring contributions from a quorum of at least $n - t$ nodes.
- Agreement on the identity of $QUAL^*$ is achieved via Randomized Asynchronous Binary Byzantine Agreement (ABBA) with Verifiable Threshold Common Coins (Cachin, Kursawe, Petzold 2000; Kate et al. 2012).
- Under the asynchronous adversary model, the common coin ensures expected $O(1)$ round complexity, guaranteeing termination with probability 1.

---

## 3. Defense Against Known Attack Vectors

| Attack Vector | Mechanism & Vulnerability | SARAL V3 Cryptographic Defense |
|---|---|---|
| **Malicious Dealer (Invalid Shares)** | Dealer sends inconsistent polynomial evaluations to different nodes. | **Bivariate Symmetry & Pedersen Verification:** Each node verifies $A_{i, j}(y) = B_{j, i}(y)$ and $Q_{i, j} = A_{i, j}(0)G + B_{i, j}(0)H$. Inconsistent shares fail predicate and are excluded from $QUAL^*$. |
| **Commitment Equivocation** | Byzantine dealer sends different commitment matrices $C^{(i)}$ to different nodes. | **AVSS ECHO/READY Quorum:** Nodes only proceed if $\ge n-t$ matching commitments are agreed upon across the committee via AVSS reliable broadcast. |
| **Key Bias / Last-Dealer Attack** | Adversary waits to see honest contributions before choosing their own $z_i$. | **Pedersen Information-Theoretic Blinding:** Contributions are committed before shares are revealed. Independent blinding $z'_i$ prevents learning partial keys. |
| **Cross-Epoch Share Mixing** | Adversary attempts to combine Epoch 1 DKG shares with Epoch 2 refreshed shares. | **Epoch Invariance & Vault Isolation:** Shares are bound to strict epoch numbers $\tau$. Combining shares across epochs yields an invalid scalar that fails verification against $Y$. |
| **Scalar Field Mismatch ($N$ vs $P$)** | Operating with modulo $P$ instead of group order $N$ causes catastrophic invalid curve operations. | **Canonical P-256 Arithmetic:** All scalar additions, multiplications, and inversions strictly use group order $N = 2^{256} - 2^{224} + 2^{192} + \dots$ verified by independent test vectors. |
| **Sub-threshold Collusion** | Corrupted quorum ($< k$) attempts to reconstruct the master secret. | **Threshold Bound $k \ge t + 1$:** Any subset of size $\le t$ has zero information regarding the master secret. |
