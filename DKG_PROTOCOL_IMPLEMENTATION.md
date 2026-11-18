# SARAL Protocol V3 — Dealerless DKG Protocol Implementation Guide

**Document Version:** 1.0.0  
**Phase:** Phase 3 — Dealerless Distributed Key Generation (DKG)  
**Status:** IMPLEMENTED & CRYPTOGRAPHICALLY VERIFIED  
**Package:** `services/saral-node/dkg` & `services/coordinator/internal/rpc`

---

## 1. Mathematical Formulation

### Step 1: Contribution Generation
Each committee node $P_i$ ($i \in \{1, \dots, n\}$) acts as an independent dealer:
1. Samples random secret contribution $z_i \in_R \mathbb{Z}_N$ and random blinding factor $z'_i \in_R \mathbb{Z}_N$ using `crypto/rand`.
2. Constructs symmetric bivariate polynomials of degree $k-1$:
   $$A^{(i)}(x, y) = \sum_{m=0}^{k-1} \sum_{\ell=0}^{k-1} a^{(i)}_{m, \ell} x^m y^\ell \quad (a_{m, \ell} = a_{\ell, m}, \, a_{0,0} = z_i)$$
   $$B^{(i)}(x, y) = \sum_{m=0}^{k-1} \sum_{\ell=0}^{k-1} b^{(i)}_{m, \ell} x^m y^\ell \quad (b_{m, \ell} = b_{\ell, m}, \, b_{0,0} = z'_i)$$
3. Computes the public Pedersen commitment matrix $C^{(i)} \in \mathbb{E}(\mathbb{F}_P)^{k \times k}$:
   $$C^{(i)}_{m, \ell} = a^{(i)}_{m, \ell} \cdot G + b^{(i)}_{m, \ell} \cdot H$$
4. Evaluates univariate sub-polynomials for each peer $P_j$:
   $$f^{(i)}_j(y) = A^{(i)}(j, y), \quad f'^{(i)}_j(y) = B^{(i)}(j, y)$$
5. Dispatches encrypted AVSS distribution messages via authenticated P2P relay mesh to each peer $P_j$.

### Step 2: Verifiable Share Reception & Validation
Each participant $P_j$ evaluates shares received from dealer $P_i$:
1. Verifies univariate evaluations against the public commitment matrix:
   $$f^{(i)}_j(m) \cdot G + f'^{(i)}_j(m) \cdot H \stackrel{?}{=} \sum_{r=0}^{k-1} \sum_{\ell=0}^{k-1} (j^r m^\ell) \cdot C^{(i)}_{r, \ell}$$
2. Runs AVSS reliable broadcast (`SEND` $\to$ `ECHO` $\to$ `READY`) until $P_i$'s sharing completes.
3. Once completed, node $P_j$ obtains its valid verifiable share of $P_i$'s secret:
   $$s_{i, j} = f^{(i)}_j(0) = A^{(i)}(j, 0), \quad s'_{i, j} = f'^{(i)}_j(0) = B^{(i)}(j, 0)$$

### Step 3: Qualified Set ($QUAL^*$) Agreement
1. As soon as node $P_j$ has successfully verified and received shares from $W \ge n - t$ dealers, it proposes its candidate qualified set $QUAL_j$.
2. Participants execute Randomized Asynchronous Binary Byzantine Agreement (ABBA) with Verifiable Threshold Common Coins to agree on a single deterministic set $QUAL^*$, guaranteeing:
   $$|QUAL^*| \ge n - t$$
   and that every honest dealer whose sharing completed across the committee is included in $QUAL^*$.

### Step 4: Local Share & Public Key Aggregation
Each node $P_j$ computes its master key share $x_j$ and blinding share $x'_j$ by summing only shares from dealers $i \in QUAL^*$:
$$x_j = \sum_{i \in QUAL^*} s_{i, j} \pmod N, \quad x'_j = \sum_{i \in QUAL^*} s'_{i, j} \pmod N$$
Each node verifies its aggregated share against the sum of public commitment matrices:
$$Q_j = x_j \cdot G + x'_j \cdot H \stackrel{?}{=} \sum_{i \in QUAL^*} \sum_{\ell=0}^{k-1} j^\ell \cdot C^{(i)}_{\ell, 0}$$
The master public key $Y$ is computed deterministically:
$$Y = \sum_{i \in QUAL^*} C^{(i)}_{0, 0} = x \cdot G$$
No participant or coordinator ever computes or sees the master private key:
$$x = \sum_{i \in QUAL^*} z_i \pmod N$$

### Step 5: Vault Persistence
Node $P_j$ writes its active share record to its persistent encrypted vault:
```json
{
  "epoch": 1,
  "nodeId": "saral-node-1",
  "share": "<x_j in hex>",
  "blinding": "<x'_j in hex>",
  "commitment": "<Q_j in hex>",
  "secretCommitment": "<Y in hex>",
  "k": 5,
  "t": 4,
  "committee": ["saral-node-1", ..., "saral-node-15"],
  "state": "ACTIVE"
}
```
The vault encrypts the record with AES-256-GCM using the node's local vault master key and writes it with `0600` POSIX file permissions.

---

## 2. Code Walkthrough

### 2.1 Session State Machine (`services/saral-node/dkg/session.go`)
- `NewSession`: Instantiates the session, validates parameters against theoretical bounds ($n > 3t$, $n - 2t \ge k$, $k \ge t + 1$), and initializes participant records.
- `StartContribution`: Samples secret scalars $z_i, z'_i$, samples symmetric bivariate polynomials, and creates the AVSS sharing session.
- `RecordPeerContribution`: Registers peer public commitments and AVSS session IDs.
- `OnAVSSShareReceived`: Triggered via observer callback when a peer's AVSS sharing terminates; stores verified share $s_{i, j}$.
- `DetermineQualifiedSet`: Evaluates whether $n-t$ shares have arrived; proposes candidate $QUAL$ set.
- `AggregateShares`: Computes $x_j = \sum_{i \in QUAL^*} s_{i,j} \pmod N$, computes Master Public Key $Y$, verifies commitment equality, and commits the share to `vault.ShareStore`.
- `GetPublicView`: Extracts non-sensitive public progress for coordinator telemetry, strictly omitting private shares.

### 2.2 Protocol Engine (`services/saral-node/dkg/engine.go`)
- Maintains active DKG sessions keyed by `sessionId`.
- Listens for P2P relay messages:
  - `MessageTypeDKGInit`: Handled via coordinator REST trigger.
  - `MessageTypeDKGContribution`: Broadcasts peer public commitment matrix $C^{(i)}$ and AVSS parameters.
- Implements `avss.SharingCompletionListener` to seamlessly receive notifications when AVSS sessions terminate.

### 2.3 Coordinator Orchestration (`services/coordinator/internal/rpc/dkg.go`)
Provides authenticated JSON-RPC 2.0 endpoints for cluster operators:
- `saral_startDkg`: Resolves committee nodes, validates thresholds, issues `/node/dkg/init` and `/node/dkg/start` RPCs to all committee nodes.
- `saral_getDkgStatus`: Queries local public DKG states across committee nodes; resolves consensus status.
- `saral_getDkgParticipants`: Returns participant contribution and qualified set status.
- `saral_getDkgPublicKey`: Returns the agreed NIST P-256 master public key $Y$.
- `saral_getDkgVerificationStatus`: Returns cryptographic verification proofs and consensus flags.

### 2.4 TypeScript SDK (`packages/saral-sdk`)
Exposes typed client methods:
```typescript
const client = new SaralClient({ coordinatorUrl: 'http://localhost:9001' });
await client.authenticate('operator', 'admin');

// Start DKG on Global 15-node Committee
const dkg = await client.startDkg({
  committeeId: 'saral-global-15',
  n: 15,
  k: 5,
  t: 4,
});

// Poll Status
const status = await client.getDkgStatus(dkg.sessionId);
console.log(`Master Public Key: ${status.masterPublicKey}`);
```

### 2.5 Web Dashboard (`apps/web/src/App.tsx`)
Provides an interactive real-time control panel:
- Committee topology selector (Global 15-node vs Domain 5-node).
- Real-time progress bar tracking completed nodes.
- Prominent display of the agreed Master Public Key $Y$.
- Visual breakdown of Qualified Set ($QUAL^*$) members.
- Participant verification table showing individual node statuses.
