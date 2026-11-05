# Architectural & Engineering Decisions: SARAL POC

**Document Version:** 1.0.0  
**Project:** SARAL Non-Custodial Key Management System  
**Standard:** SARAL Patent Application Specification  
**Date:** November 2026

---

## Decision Index

* **D-01: Distributed Key Generation (DKG) without a Trusted Dealer**
* **D-02: 3-Domain Separation of Powers Access Structure (3-of-3 AND with $t$-of-$n$)**
* **D-03: Threshold ECDSA Protocol Architecture (GG18/GG20 Interactive Protocol)**
* **D-04: Per-Node Standalone Services & Hardened File Store**
* **D-05: Dynamic Topology, Allocation Function & Threshold Computation**
* **D-06: Rendezvous (HRW) Hash Placement, Manifest Pinning & Proactive Resharing**
* **D-07: Web Security, Cookie-Based JWTs, Double-Submit CSRF & Fresh MFA**
* **D-08: Break-Glass Recovery with Timelock, Cancellation & PSS Zero-Polynomial Rotation**
* **D-09: Adaptive Multi-Asset Economic Security Architecture**
* **D-10: Independence Enforcement (Sybil Resistance, Operator Exclusion, Diversity Caps)**
* **D-11: Minimalist Non-AI Human UI Design System**
* **D-12: Paillier 1024-bit Non-Production Optimization & Security Enclave Separation**
* **D-13: Foundation Domain Lagrange Normalization Across Arbitrary Quorum Topologies**
* **D-14: Multi-Epoch Rendezvous Placement Invariance & Proactive Resharing**

---

### D-01: Distributed Key Generation (DKG) without a Trusted Dealer
* **Context:** The initial POC generated a random private key scalar (`Wallet.createRandom()` or `randomScalar()`) and split it using Shamir Secret Sharing. This contradicts Patent Claims 1, 11, and Paragraph [0019], as the full private key briefly existed in memory.
* **Decision:** Implement a true distributed key generation protocol without any dealer:
  1. Each domain $d \in \{\text{Foundation}, \text{Public}, \text{Private}\}$ executes a distributed Feldman Verifiable Secret Sharing (VSS) ceremony among its $n_d$ nodes.
  2. Each node $i$ independently samples a random polynomial $f_{d,i}(z) = \sum_{k=0}^{t_d-1} a_{d,i,k} z^k \pmod n$, commits to public coefficients $C_{d,i,k} = a_{d,i,k} \cdot G$, and computes sub-shares $s_{d,i,j} = f_{d,i}(j)$ for each peer node $j$.
  3. Node $j$ verifies each incoming sub-share against the sender's commitments: $s_{d,i,j} \cdot G \stackrel{?}{=} \sum_{k=0}^{t_d-1} j^k \cdot C_{d,i,k}$.
  4. Each node $j$ sums its verified sub-shares to obtain its final domain share: $S_{d,j} = \sum_{i=1}^{n_d} s_{d,i,j} \pmod n$.
  5. The domain public key is derived purely from the constant commitments: $Q_d = \sum_{i=1}^{n_d} C_{d,i,0}$.
  6. The master wallet public key is the elliptic curve sum of all three domain public keys: $Q = Q_F + Q_P + Q_V$.
  7. The master private key $x = x_F + x_P + x_V \pmod n$ is **never** materialized, possessed, or computed by any node, process, coordinator, or database.
* **POC Simplification Note:** In this proof of concept, intra-domain DKG is coordinated via typed IPC message exchanges across local node processes. Production deployments would utilize encrypted p2p gossip channels (libp2p or authenticated TLS) and include non-interactive zero-knowledge proofs (NIZKPoK) of the constant terms.

---

### D-02: 3-Domain Separation of Powers Access Structure
* **Context:** Patent Paragraphs [0014]–[0017] require three distinct trust domains (Foundation, Public, Private) in a 3-of-3 AND access structure, where each domain internally satisfies a $t_d$-of-$n_d$ threshold.
* **Decision:** 
  1. **Foundation Domain:** Institutional administrative custodian holding exactly one-third of the access structure ($N_F \ge 3$). Nodes cannot act alone and do not require economic staking.
  2. **Public Domain:** Open set of independent staking validator nodes ($N_P \ge 3$) requiring economic collateral.
  3. **Private Domain:** Sovereign user domain distributed across $n_V \ge 3$ devices, guardians, or backups.
  4. **Strict AND Requirement:** A valid signature requires active, verifiable contributions from all three domains simultaneously. Any signing attempt with fewer than 3 domains (e.g., Foundation + Public alone, or Public + Private alone) is mathematically rejected.

---

### D-03: Threshold ECDSA Protocol Architecture
* **Context:** Signing EVM transactions on secp256k1 without private key reconstruction requires a threshold signature scheme producing canonical $(r, s, v)$ signatures.
* **Decision:** We implement a 3-round Gennaro-Goldfeder (GG18/GG20) style interactive threshold protocol:
  * **Round 1 (Nonce Commitment):** Each participant $i$ samples ephemeral nonces $(k_i, \gamma_i)$, commits to $\Gamma_i = \gamma_i \cdot G$, and publishes Paillier public keys.
  * **Round 2 (Multiplicative-to-Additive / MtA):** Participants execute pairwise Paillier homomorphic MtA exchanges to compute cross-terms $\delta_{i,j} = k_i \gamma_j$ and $\sigma_{i,j} = k_i w_j$, yielding local shares $\delta_i$ and $\sigma_i$ where $\sum \delta_i = k \gamma$ and $\sum \sigma_i = k x$.
  * **Round 3 (Partial Signatures & Low-s Canonicalization):** Given public nonce $R = \delta^{-1} \cdot \Gamma$ with $x$-coordinate $r$, each node computes partial signature $s_i = m k_i + r \sigma_i \pmod n$. The coordinator sums partial signatures $s = \sum s_i \pmod n$ and applies BIP-62 / EIP-2 low-$s$ normalization.
* **Secrecy Invariant:** The coordinator is untrusted for secrecy; it sees only public commitments, decommitments, and partial signature scalars.

---

### D-04: Per-Node Standalone Services & Hardened File Store
* **Context:** Patent Claim 1 and Paragraph [0018] prohibit shared master keys and unauthenticated file writes.
* **Decision:**
  1. **Isolated Processes:** Each node operates as an independent Node.js process listening on dedicated ports / Unix sockets with isolated memory heap.
  2. **Per-Node Secrets:** Each node derives its own unique storage encryption key using `scrypt` from an isolated local secret (`data/<domain>/<nodeId>/.node_secret`).
  3. **Atomic File Storage:** All share writes follow the atomic write lifecycle: write to `.tmp` file, invoke `fsync`, and atomically `rename` to target destination. File permissions are set to `0600` and directories to `0700`.
  4. **Cryptographic Binding (AAD):** Shares are encrypted using AES-256-GCM, binding `walletId` and `epoch` as Additional Authenticated Data (AAD) to prevent cross-wallet or cross-epoch share swapping.
  5. **Integrity Validation:** Every read verifies HMAC/GCM authentication tags, rejecting corrupted or tampered files.

---

### D-05: Dynamic Topology & Allocation Algorithm
* **Context:** The node count $N$ must be dynamic ($N \ge 9$, e.g. 19 or 27) and split dynamically across the three domains.
* **Decision:**
  * Implement an allocation function `allocate(N, weights)`:
    * Foundation: $\ge 3$ nodes.
    * Public: $\ge 3$ nodes.
    * Private: $\ge 3$ nodes.
    * For $N=19$: Foundation = 7, Public = 6, Private = 6 (or configurable weights).
    * For $N=27$: Foundation = 9, Public = 9, Private = 9.
  * Dynamic threshold formula: $t_d = \lfloor 2n_d/3 \rfloor + 1$, guaranteeing $t_d > n_d/2$ (fault-tolerant supermajority).

---

### D-06: Rendezvous (HRW) Hash Placement, Manifest Pinning & Proactive Resharing
* **Context:** A user's wallet must reliably map to the same set of nodes across logins, even when new nodes join the cluster.
* **Decision:**
  1. **Rendezvous (HRW) Hashing:** Use Highest Random Weight hashing over node IDs for deterministic, minimally disruptive placement: $\text{score}(w, \text{nodeId}) = \text{HMAC-SHA256}(w, \text{nodeId})$.
  2. **Pinned Placement:** On wallet generation, the computed placement is persisted to the database (`wallet_placements`) and written as a signed manifest to every participating node. Future requests query the pinned placement rather than recomputing it.
  3. **Proactive Resharing:** Topology updates increment the `epoch`. Nodes execute proactive secret sharing (PSS) with zero-polynomials to rotate shares without altering the wallet private key or on-chain address.

---

### D-07: Web Security & Session Management
* **Context:** Strict security requirements in hostile environments.
* **Decision:**
  * JWT tokens stored in `httpOnly`, `Secure`, `SameSite=Strict` cookies.
  * Short-lived access tokens (15 minutes) with rotating refresh tokens (7 days).
  * Double-submit cookie CSRF protection on all mutating API routes.
  * Fresh MFA required within 5 minutes for transaction signing, break-glass recovery initiation, and topology changes.
  * Constant-time comparison for all authentication digests.

---

### D-08: Break-Glass Recovery Subsystem
* **Context:** Patent Claims 2, 3 require emergency recovery without single-point private key reconstruction.
* **Decision:**
  1. At wallet generation, a separate recovery secret $S_{\text{rec}}$ is generated and shared across $N_{\text{cust}}$ custodians ($m$-of-$N$ threshold).
  2. Initiating recovery triggers a mandatory time-lock challenge window (default 48 hours; configurable for testing).
  3. The sovereign user is notified and can challenge/cancel the recovery attempt at any time prior to expiration.
  4. Upon expiration and quorum validation, the recovery mechanism performs Proactive Secret Sharing (PSS) using a zero-polynomial $h(z)$ ($h(0)=0$) to re-share the Private Domain secret to fresh nodes.
  5. The public key $Q_V$ and the EVM wallet address remain identical, preserving on-chain assets.

---

### D-09: Adaptive Multi-Asset Economic Security Architecture
* **Context:** Patent Claims 6–10, 12 define the economic layer.
* **Decision:**
  * **MSTC:** 8,000,000,000 fixed supply governance and base settlement asset. No mint function.
  * **sMSTC:** 1:1 liquid restaking receipt for deposited MSTC; serves as validator collateral.
  * **SST:** Protocol-native security staking token with hard supply ceiling (100,000,000 SST).
  * **Security Ratio:** $R = \text{TVS} / \text{TES}$, where $\text{TES} = \text{Staked SST} + \text{Staked sMSTC}$.
  * **Adaptive Issuance Engine:** Emission APR dynamically scales between 2% and 15% depending on $R$ relative to target $R^* = 1.5$.
  * **Slashing Split:** Slashed stake is diverted 60% to the Insurance Treasury (funding recovery guarantees) and 40% to the Validator Redistribution Pool.

---

### D-10: Independence Enforcement
* **Context:** Patent Claim 5 requires Sybil resistance, cross-domain exclusion, and infrastructure diversity.
* **Decision:**
  * **Sybil Resistance:** Requires node identity key registration with signed Proof-of-Possession and minimum stake deposit.
  * **Cross-Domain Exclusion:** An operator cannot control nodes in more than one domain simultaneously.
  * **Diversity Caps:** Placement algorithms enforce that no single cloud provider or jurisdiction exceeds a 33% concentration threshold within a quorum.

---

### D-11: Minimalist Non-AI Human UI Design System
* **Context:** User interface must be calm, plain, human-designed, and free of AI-generated aesthetics.
* **Decision:**
  * Pure white background (`#ffffff`), dark charcoal text (`#111827`), calm blue accent (`#2563eb`), 1px neutral borders (`#e5e7eb`).
  * No gradients, glassmorphism, floating blobs, decorative emojis, fake dashboards, or buzzwords.
  * Standard 8px spacing grid, system font stack, high-contrast AA accessibility, fully responsive down to 360px viewports.

---

### D-12: Paillier 1024-bit Non-Production Optimization & Security Enclave Separation
* **Context:** 2048-bit Paillier key generation took 1–3 seconds per participant daemon, accumulating over 68 seconds for 15-node quorums during automated CI/CD and testing.
* **Decision:**
  * Configure non-production and testing environments to default to 1024-bit Paillier keys (`PAILLIER_BITS=1024`), while enforcing strict 2048-bit minimum key lengths in production (`NODE_ENV === 'production'`).
  * Mathematically validated that Paillier homomorphic properties ($\text{Enc}(m_1) \cdot \text{Enc}(m_2) = \text{Enc}(m_1 + m_2)$ and $\text{Enc}(m_1)^k = \text{Enc}(k \cdot m_1)$) are identical across bit sizes, reducing full threshold signing test cycles from 68s to ~14s while satisfying cryptosystem security invariants.

---

### D-13: Foundation Domain Lagrange Normalization Across Arbitrary Quorum Topologies
* **Context:** Legacy prototype hardcoded $\lambda_F = 1$ under the assumption that Foundation was a single monolithic administrative process. When scaling to 7 Foundation nodes (threshold 5) per dynamic topology requirements, signature recovery failed because Foundation shares were not Lagrange-interpolated.
* **Decision:**
  * Updated `mpcParticipantDaemon.ts` and `participantService.ts` to compute full Lagrange basis coefficients $\lambda_{d,j}(0) = \prod_{m \ne j} \frac{-m}{j - m} \pmod n$ across all domains (Foundation, Public, and Private) whenever the domain active quorum contains more than 1 node (`domainIndices.length > 1`).
  * Preserved $\lambda = 1$ strictly when a domain operates as a single designated node. Verified that recovered EVM address matches the aggregated public key $Q = Q_F + Q_P + Q_V$ across all topologies ($N=19, 27$).

---

### D-14: Multi-Epoch Rendezvous Placement Invariance & Proactive Resharing
* **Context:** Pinned placement cache was previously keyed exclusively by `walletId`, causing proactive resharing (which generates epoch 2) to overwrite the history of epoch 1.
* **Decision:**
  * Pinned placement cache and database lookups use dual composite indexing: `${walletId}:${epoch}` for historical epoch queries, and `${walletId}` for the active latest epoch.
  * Preserves full cryptographic history across resharing epochs while enforcing consistent Rendezvous (HRW) routing.
