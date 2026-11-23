# SARAL Protocol Cryptographic & Consensus Specification

This document details the mathematical foundations, quorum parameters, consensus protocols, and security invariants implemented in the SARAL Separation-of-Powers Cryptographic Key Infrastructure.

---

## 1. Architectural Overview & Separation of Powers

SARAL implements a non-custodial, dealerless threshold key infrastructure governed by three sovereign domains:

1. **Foundation Domain** (5 Nodes) — Protocol governance and regulatory oversight.
2. **Public Domain** (5 Nodes) — Decentralized community-operated verifiers.
3. **Private Domain** (5 Nodes) — High-security enterprise and institutional vault participants.

```text
               +--------------------------------------------+
               |        SARAL Auth Server (Node.js)         |
               |       Dynamic RAM Address Derivation       |
               +--------------------------------------------+
                     |                 |                 |
     secp256k1/ed25519 | secp256k1/ed25519 | secp256k1/ed25519
                     v                 v                 v
            +----------------+ +----------------+ +----------------+
            |   Foundation   | |     Public     | |    Private     |
            |  Coordinator   | |  Coordinator   | |  Coordinator   |
            +----------------+ +----------------+ +----------------+
              |   (5 nodes)    |  |   (5 nodes)    |  |   (5 nodes)    |
              v                v  v                v  v                v
         [F1 ... F5]         [P1 ... P5]         [R1 ... R5]
```

### Multi-Domain Additive Key Derivation
For each supported elliptic curve, each domain collaboratively runs a Dealerless Distributed Key Generation (DKG) session to establish a domain master public key:
- Foundation: $Y_F = x_F \cdot G$
- Public: $Y_P = x_P \cdot G$
- Private: $Y_R = x_R \cdot G$

The user's unified master public key $Y$ is the point sum across all three sovereign domains:
$$Y = Y_F + Y_P + Y_R = (x_F + x_P + x_R) \cdot G$$

No single domain, coordinator, node, or database ever holds the private scalar $x = x_F + x_P + x_R$. Each node holds only an encrypted Shamir/Pedersen evaluation share within its local AES-256-GCM vault.

---

## 2. HybridVSS Protocol (Kate-Huang-Goldberg)

SARAL implements Asynchronous Verifiable Secret Sharing (AVSS) based on bivariate polynomials as formalized by Kate, Huang, and Goldberg (ACNS 2012 / ePrint 2012/377).

### Mathematical Setup
Let $\mathbb{F}_q$ be the scalar field of the target elliptic curve with generator $G$ and independent commitment generator $H$.
A dealer $D_i$ selects two symmetric bivariate polynomials of degree $(t, k-1)$:
- Secret polynomial: $F(x, y) = \sum_{l=0}^{t} \sum_{m=0}^{k-1} a_{lm} x^l y^m$ with secret $s = F(0, 0)$.
- Blinding polynomial: $F'(x, y) = \sum_{l=0}^{t} \sum_{m=0}^{k-1} a'_{lm} x^l y^m$ with blinding factor $s' = F'(0, 0)$.

Pedersen bivariate commitments are broadcast:
$$C_{lm} = a_{lm} \cdot G + a'_{lm} \cdot H \quad \forall l \in [0, t], m \in [0, k-1]$$
Feldman public key commitments:
$$V_{lm} = a_{lm} \cdot G \quad \forall l \in [0, t], m \in [0, k-1]$$

Each participant $P_j$ receives sub-polynomial shares:
$$f_j(y) = F(j, y), \quad f'_j(y) = F'(j, y)$$
and verifies against commitments:
$$f_j(m) \cdot G + f'_j(m) \cdot H \stackrel{?}{=} \sum_{l=0}^{t} j^l C_{lm} \quad \forall m \in [0, k-1]$$

### Paper Quorums & Parameters
For a committee of size $n$, maximum Byzantine malicious nodes $t$, and crash faults $f$:

| Parameter | Formula | Standard Cluster ($n=5, t=1, f=0$) | Purpose |
| :--- | :--- | :---: | :--- |
| **Echo Quorum** | $Q_{\text{echo}} = \left\lceil \frac{n + t + 1}{2} \right\rceil$ | $4$ | Guarantees intersecting honest sets in Bracha broadcast |
| **Ready-Step Quorum** | $Q_{\text{ready-step}} = t + 1$ | $2$ | Triggers amplification broadcast of READY |
| **Completion Quorum** | $Q_{\text{complete}} = 2t + f + 1$ | $3$ | Concludes reliable AVSS sharing acceptance |
| **Reconstruction Bound** | $k \le n - 2t - f$ | $k = 3 \le 5 - 2 = 3$ | Guarantees sufficient honest points to reconstruct |

### Liveness Analysis: Paper Quorums vs Dual-Threshold Echo Quorum

A common theoretical formulation for dual-threshold VSS sets:
$$Q_{\text{dual}} = \left\lceil \frac{n + k + t + 1}{2} \right\rceil$$

For $n=5, k=3, t=1$:
$$Q_{\text{dual}} = \left\lceil \frac{5 + 3 + 1 + 1}{2} \right\rceil = \left\lceil \frac{10}{2} \right\rceil = 5$$

#### Crash Fault Liveness Failure with $Q_{\text{dual}} = 5$:
- If **1 node crashes or network partitions** ($f=1$), only 4 nodes are online.
- Maximum possible ECHOs any node can receive is $4$.
- Because $4 < Q_{\text{dual}} = 5$, **no node can ever emit READY**.
- **Result:** Complete protocol deadlock (0% liveness).

#### Safety and Liveness Guarantee with Paper Quorums ($Q_{\text{echo}} = 4$):
- **Liveness:** When 1 node is offline ($n - 1 = 4$ alive nodes), all 4 honest nodes receive 4 ECHOs $\ge Q_{\text{echo}} = 4$, and all broadcast READY. Each receives 4 READYs $\ge Q_{\text{complete}} = 3$, completing VSS successfully.
- **Safety:** Any two subsets of size $Q_{\text{echo}} = 4$ in $n=5$ intersect in at least $4 + 4 - 5 = 3$ nodes. With $t=1$, at least $3 - 1 = 2 \ge 1$ honest node intersects, preventing split-brain equivocation.
- **Reconstruction:** Honest completed shares are $n - t - f = 5 - 1 - 1 = 3 \ge k = 3$. Hence, the degree-$(k-1)$ polynomial can always be reconstructed by honest nodes.

---

## 3. Leader-Based HybridDKG Protocol

SARAL implements the complete leader-based HybridDKG protocol described in Section 5 of Kate-Huang-Goldberg.

### Protocol Message Flow

```text
Participants                      Leader (pi(r))                   Coordinators
    │                                   │                               │
    ├── [1] Complete AVSS Sharings ────>│                               │
    ├── [2] Send ValidityCertificates ─>│                               │
    │   (Ed25519 signed)                │                               │
    │                                   │                               │
    │                                   ├── [3] Form QUAL (|QUAL| >= k) │
    │<── [4] HYBRID_DKG_PROPOSAL ───────┤   Attach Certificates         │
    │                                   │                               │
    ├─── [5] Broadcast HYBRID_DKG_ECHO ────────────────────────────────>│
    │    (Echo Quorum >= 4)             │                               │
    │                                   │                               │
    ├─── [6] Broadcast HYBRID_DKG_READY ───────────────────────────────>│
    │    (Ready Quorum >= 3)            │                               │
    │                                   │                               │
    ├─── [7] Combine Shares in RAM ─────┼──────────────────────────────>│
    │    Y = sum_{i in QUAL} V_{i,0}    │                               │
    │                                   │                               │
    └─── [8] HYBRID_DKG_COMPLETE ───────┴──────────────────────────────>│
```

### 1. Validity Certificate Collection
When a participant $P_j$ verifies dealer $D_i$'s AVSS sharing, it creates and signs a `ValidityCertificate`:
$$\sigma_{j, i} = \text{Sign}_{\text{sk}_j}(m), \quad m = \text{SessionID} \parallel D_i \parallel P_j \parallel \text{Hash}(C_i) \parallel \text{Epoch}$$
The certificate is broadcast to the committee.

### 2. Leader Proposal (Optimistic Phase)
The designated leader for round $r$ is deterministically chosen via cyclic permutation:
$$\text{Leader}(r) = \text{Committee}[(r-1) \pmod n]$$
Once the leader collects $\ge t+1$ certificates for $\ge n-t$ dealers (or at least threshold $k$), it forms the Qualified Set $\text{QUAL}$ and broadcasts `HYBRID_DKG_PROPOSAL`.

### 3. Reliable Dissemination (Echo & Ready)
- Each node verifies the leader's Ed25519 signature, checks validity certificates for every dealer in $\text{QUAL}$, and verifies $|\text{QUAL}| \ge k$. Upon validation, it broadcasts `HYBRID_DKG_ECHO`.
- Upon receiving $Q_{\text{echo}} \ge \lceil (n+t+1)/2 \rceil$ matching ECHOs (or $t+1$ READYs), a node broadcasts `HYBRID_DKG_READY`.
- Upon receiving $Q_{\text{complete}} \ge 2t+f+1$ READYs, the node finalizes the agreed $\text{QUAL}$.

### 4. Pessimistic Leader Change
If the leader crashes, equivocates, or fails to propose within `SARAL_LEADER_TIMEOUT_MS`, nodes broadcast `HYBRID_DKG_LEADER_CHANGE`.
Upon gathering $t+1$ leader change messages for round $r$, nodes advance to round $r+1$, deposing the faulty leader and rotating to $\text{Leader}(r+1)$.

---

## 4. Multi-Curve Key Combination & Address Derivation

SARAL natively supports multiple distinct elliptic curves across the same 3-domain architecture:

### 1. secp256k1 (MST EVM & Bitcoin Taproot)
- **Field Order:** $q_{\text{secp}} = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BB5D9652C090F4A76}$
- **Generator Point:** $G_{\text{secp}}$ (Standard secp256k1 base point)
- **Commitment Generator:** $H_{\text{secp}} = \text{SHA256}(G_{\text{secp}}) \cdot G_{\text{secp}}$
- **MST EVM Address:** Derived via Keccak-256 hash of the 64-byte uncompressed $(x, y)$ coordinates, formatted with EIP-55 checksum:
  $$\text{Address}_{\text{MST}} = \text{toChecksumAddress}(\text{Keccak256}(x \parallel y)[12:32])$$
- **Bitcoin Taproot Address:** Uses BIP-340 32-byte x-only public key from the combined point $Y$, formatted as Bech32m witness v1 (`tb1p...`).
  - *Parity Invariant:* Points $(x, y)$ and $(x, -y \pmod p)$ share the identical $x$-coordinate and generate the identical Taproot address without private key exposure.

### 2. ed25519 (Solana Devnet)
- **Field Order:** $q_{\text{ed}} = 2^{252} + 27742317777372353535851937790883648493$
- **Generator Point:** $G_{\text{ed}}$ (Edwards-25519 base point)
- **Commitment Generator:** $H_{\text{ed}} = \text{SHA256}(G_{\text{ed}}) \cdot G_{\text{ed}}$
- **Solana Address:** Standard 32-byte Ed25519 public key encoded with Base58:
  $$\text{Address}_{\text{Solana}} = \text{Base58Encode}(\text{CompressedBytes}(Y))$$

---

## 5. Security & Isolation Invariants

| ID | Invariant | Enforcement Mechanism |
| :--- | :--- | :--- |
| **R1** | All 3 domains (15 nodes) must participate | Coordinators for Foundation, Public, and Private must all return valid public points before address derivation succeeds. |
| **R2** | Exactly one wallet per user | PostgreSQL unique index on `userId`; idempotent lookup in `createOrGetWallet`. |
| **R3** | Returning user reuses DKG sessions | Existing `READY` wallets immediately re-derive addresses from stored `dkgSessionIds`; never launch fresh DKG. |
| **R4** | Zero private key persistence or reconstruction | Node shares encrypted with AES-256-GCM; reconstruction symbols excluded from production binaries via `//go:build test_only`. |
| **R5** | Zero address/public key storage | Addresses derived strictly in volatile memory (RAM); database stores only opaque string IDs (`key-mst-...`). |
| **R6** | Dynamic topology from `.env` | All counts ($n, k, t, f$) and committee hostnames read from configuration at runtime. |

---

## 6. Notices & Operational Scope

> [!NOTE]
> **Proactive Common Coin Simulation Notice:**
> The `proactive` package agreement implementation includes a deterministic pseudo-random common coin generator utilized exclusively for integration testing. In a full production deployment operating under an asynchronous Byzantine network, the common coin must be backed by a threshold PRF or BLS threshold signature scheme to guarantee asynchronous termination.
