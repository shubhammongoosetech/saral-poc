# SARAL POC — 3-Domain Separation of Powers Security Architecture

**Author:** Principal Blockchain Protocol Architect & Distributed Systems Engineer  
**Date:** November 18, 2026  

---

## 1. Architectural Philosophy: The Three Domains

The SARAL architecture establishes an uncompromisable, trust-minimized institutional security model through a cryptographic access structure based on the **Three-Domain Separation of Powers**:

```
                              +---------------------------------------+
                              |         MASTER DISTRIBUTED KEY        |
                              |              Q = Q_F + Q_P + Q_U      |
                              |              x = x_F + x_P + x_U      |
                              +---------------------------------------+
                                        /          |          \
                                       /           |           \
                                      /            |            \
                +------------------------+  +----------------+  +---------------------+
                |   FOUNDATION DOMAIN    |  | PUBLIC DOMAIN  |  |   PRIVATE DOMAIN    |
                | Institutional/Auditors |  |   Validators   |  |   Sovereign User    |
                |     Secret: x_F        |  |  Secret: x_P   |  |    Secret: x_U      |
                |   Nodes: n_F, Quorum: t_F| |Nodes: n_P, t_P |  |Nodes: n_U, Quorum: t_U|
                +------------------------+  +----------------+  +---------------------+
```

1. **Foundation Domain ($\text{FOUNDATION}$):**
   Regulatory, compliance, and institutional auditing nodes. Enforces high-level security policies, AML/KYC requirements, and prevents unilateral user or validator compromises.
2. **Public Domain ($\text{PUBLIC}$):**
   Decentralized, independent validator nodes. Ensures network liveness, consensus integrity, and prevents institutional censorship.
3. **Private Domain ($\text{PRIVATE}$):**
   User sovereign nodes (browser sandboxes, mobile devices, hardware enclaves). Ensures that no transaction can ever be signed without explicit end-user authorization.

---

## 2. Mathematical Formalization

### A. Key Derivation & Additive Separation
Let $\mathbb{G}$ be a cryptographic group of prime order $N$ with generator $G$ (for secp256k1) or $B$ (for Edwards25519).
Each domain $D \in \{F, P, U\}$ independently generates its domain secret $x_D$ and domain public key $Q_D$:
$$Q_F = x_F \cdot G, \quad Q_P = x_P \cdot G, \quad Q_U = x_U \cdot G$$
The master collective public key $Q$ is:
$$Q = Q_F + Q_P + Q_U = (x_F + x_P + x_U) \cdot G$$
The master private key $x = x_F + x_P + x_U \pmod N$ is never computed, instantiated, or stored anywhere.

### B. Within-Domain Verifiable Secret Sharing (VSS)
Within each domain $D$, the secret $x_D$ is shared using a $(t_D, n_D)$ polynomial:
$$f_D(\xi) = x_D + a_{D,1} \xi + a_{D,2} \xi^2 + \dots + a_{D, t_D-1} \xi^{t_D-1} \pmod N$$
Each node $i \in \{1, \dots, n_D\}$ receives share:
$$s_{D,i} = f_D(i) \pmod N$$
Public Feldman commitments $C_{D,k} = a_{D,k} \cdot G$ guarantee verifiability:
$$s_{D,i} \cdot G \stackrel{?}{=} \sum_{k=0}^{t_D-1} i^k \cdot C_{D,k}$$

### C. Multi-Party Threshold Signing Across 3 Domains
When signing message $m$, an active quorum $S_D \subseteq \{1, \dots, n_D\}$ with $|S_D| \ge t_D$ participates from each domain $D \in \{F, P, U\}$.
The within-domain Lagrange coefficient for node $i \in S_D$ is:
$$\lambda_{i, S_D} = \prod_{j \in S_D, j \ne i} \frac{j}{j - i} \pmod N$$
By the Lagrange interpolation theorem:
$$\sum_{i \in S_D} \lambda_{i, S_D} \cdot s_{D,i} = f_D(0) = x_D \pmod N$$
Each node generates nonces and computes its partial signature share:
$$z_{D,i} = k_{D,i} + e \cdot \lambda_{i, S_D} \cdot s_{D,i} \pmod N$$
The coordinator aggregates partial shares across all three active domain quorums:
$$z = \sum_{D \in \{F, P, U\}} \sum_{i \in S_D} z_{D,i} = \sum k_{D,i} + e \cdot \left( \sum_{i \in S_F} \lambda_i s_{F,i} + \sum_{j \in S_P} \lambda_j s_{P,j} + \sum_{k \in S_U} \lambda_k s_{U,k} \right)$$
$$z = R_{\text{total}} + e \cdot (x_F + x_P + x_U) = R_{\text{total}} + e \cdot x \pmod N$$
Multiplying by $G$:
$$z \cdot G = R_{\text{total}} + e \cdot (x_F \cdot G + x_P \cdot G + x_U \cdot G) = R_{\text{total}} + e \cdot Q$$
The resulting signature $(R_{\text{total}}, z)$ is valid under the group public key $Q$.

---

## 3. Cryptographic Proof: Mathematical Fail-Closed Property

### Theorem (Security Against Collusion of Fewer than 3 Domains)
*Let $\mathcal{A}$ be an adversary that corrupts all nodes in any two domains (e.g. $\text{FOUNDATION}$ and $\text{PUBLIC}$) while the third domain ($\text{PRIVATE}$) is honest and uncooperative. Under the Discrete Logarithm assumption in $\mathbb{G}$, $\mathcal{A}$ cannot produce a valid signature under master public key $Q$.*

### Proof
1. Suppose $\mathcal{A}$ possesses complete knowledge of $x_F$ and $x_P$.
2. To forge a valid signature $(R, z)$ on message $m$ under public key $Q$, $\mathcal{A}$ must satisfy:
   $$z \cdot G = R + H(R, Q, m) \cdot Q$$
3. Substituting $Q = (x_F + x_P) G + Q_U$:
   $$z \cdot G - R - H(R, Q, m) (x_F + x_P) G = H(R, Q, m) \cdot Q_U$$
4. Since $\mathcal{A}$ knows $x_F, x_P$, let:
   $$z' = z - H(R, Q, m)(x_F + x_P) \pmod N$$
   Then:
   $$z' \cdot G = R + H(R, Q, m) \cdot Q_U$$
5. Producing $(R, z')$ constitutes a valid Schnorr/Ed25519 signature on message $m$ under public key $Q_U$ without knowledge of the private key $x_U$.
6. Under the unforgeability of the underlying signature scheme in the random oracle model, no polynomial-time adversary can produce such a signature with non-negligible probability.
7. Therefore, no subset of fewer than 3 domains can produce a valid signature under master public key $Q$. $\blacksquare$

---

## 4. Coordinator Fail-Closed Implementation

In `backend/src/tss/domain/ThreeDomainCoordinator.ts`, the quorum gate evaluates active participants prior to every round:

```typescript
public validateDomainQuorum(
  activeParticipants: { domain: DomainName }[],
  topology: ThreeDomainTopologyConfig
): { valid: boolean; counts: Record<DomainName, number>; reason?: string } {
  const counts = { FOUNDATION: 0, PUBLIC: 0, PRIVATE: 0 };
  for (const p of activeParticipants) counts[p.domain]++;

  if (counts.FOUNDATION < topology.foundation.threshold) {
    return { valid: false, counts, reason: 'Foundation threshold not met' };
  }
  if (counts.PUBLIC < topology.public.threshold) {
    return { valid: false, counts, reason: 'Public threshold not met' };
  }
  if (counts.PRIVATE < topology.private.threshold) {
    return { valid: false, counts, reason: 'Private threshold not met' };
  }
  return { valid: true, counts };
}
```

If any domain count falls below its required threshold $t_D$, the session terminates immediately with an identifiable security error and never initiates network round trips or nonce reservations.
