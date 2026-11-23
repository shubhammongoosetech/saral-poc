# SARAL Protocol — Separation-of-Powers Cryptographic Key Infrastructure

A production-grade, dealerless threshold cryptography Web3 key infrastructure and distributed microservice mesh.

SARAL distributes network trust, identity, and control-plane orchestration across three independent sovereign realms: **Foundation Domain**, **Public Domain**, and **Private Domain** (15 nodes total). Private signing keys are never created, assembled, reconstructed, or persisted on any single server, coordinator, database, or client device.

For full mathematical proofs, quorum derivations, and formal protocol specifications, see [PROTOCOL.md](file:///home/mongoose/Poc/saral-poc/docs/PROTOCOL.md). For deployment and operational procedures, see [OPERATIONS.md](file:///home/mongoose/Poc/saral-poc/docs/OPERATIONS.md).

---

## 1. Core Architectural Invariants

1. **3-Domain Separation of Powers (15 Nodes):** Trust is split across Foundation (5 nodes) + Public (5 nodes) + Private (5 nodes). Both new and returning users must use all three domains.
2. **6-Session Multi-Curve DKG:** Each user wallet is backed by 6 distinct DKG sessions (3 domains $\times$ 2 curves: `secp256k1` and `ed25519`).
3. **RAM-Only Address Derivation (Zero Central Persistence):** The central database stores **ZERO private keys, ZERO public keys, and ZERO blockchain addresses**. The database persists only opaque string references (`key-mst-...`). Addresses are derived on-the-fly in volatile RAM upon authenticated login.
4. **Additive Multi-Domain Master Public Key:**
   $$Y = Y_{\text{foundation}} + Y_{\text{public}} + Y_{\text{private}}$$
   - For `secp256k1`: $Y_{\text{mst}} = Y_{F,\text{secp}} + Y_{P,\text{secp}} + Y_{R,\text{secp}}$ (used for MST EVM and Bitcoin Taproot)
   - For `ed25519`: $Y_{\text{sol}} = Y_{F,\text{ed}} + Y_{P,\text{ed}} + Y_{R,\text{ed}}$ (used for Solana Devnet)
5. **Strict One-User-One-Wallet Guarantee:** Exactly one logical wallet per user (`UNIQUE(user_id)`). Returning users idempotently reuse the exact same 6 DKG sessions created at onboarding; a new DKG is never run for a user with a `READY` wallet.
6. **Dynamic Configuration:** All node counts, thresholds, and URLs originate exclusively from environment configuration (`.env`). No hardcoded node counts or thresholds exist in production logic.
7. **Zero Reconstruction Symbols in Production:** Secret reconstruction functions are compiled strictly behind `//go:build test_only` and are completely absent from production binaries.

---

## 2. Architecture & Service Topology

```text
+-------------------------------------------------------------------------+
|                  React Web Frontend (Vite / Port 5173)                  |
+-------------------------------------------------------------------------+
                                     │
                                     │ HTTPS / JWT Bearer (MFA Verified)
                                     ▼
+-------------------------------------------------------------------------+
|                    Node.js Auth Server (Port 3001)                      |
|  • RFC 6238 TOTP MFA Engine          • Working Policy Geofencing Engine  |
|  • Zero-Address RAM Derivation      • Prisma ORM / PostgreSQL 16 (5432) |
+-------------------------------------------------------------------------+
             │                                │                                │
  Foundation │ (mTLS / JSON-RPC)       Public │ (mTLS / JSON-RPC)      Private │ (mTLS / JSON-RPC)
  Coord URL  │                         Coord  │                        Coord   │
  Port 9001  │                         Port 9002                       Port 9003
             ▼                                ▼                                ▼
   +--------------------+           +--------------------+           +--------------------+
   |     Foundation     |           |       Public       |           |      Private       |
   |    Coordinator     |           |    Coordinator     |           |    Coordinator     |
   +--------------------+           +--------------------+           +--------------------+
             │                                │                                │
      mTLS 1.3 Mesh                    mTLS 1.3 Mesh                    mTLS 1.3 Mesh
             ▼                                ▼                                ▼
     5 Foundation Nodes                 5 Public Nodes                  5 Private Nodes
     (saral-foundation-1..5)          (saral-public-1..5)              (saral-private-1..5)
     Ports: 9101-9105                 Ports: 9106-9110                 Ports: 9111-9115
     • Local AES-256 Vaults           • Local AES-256 Vaults           • Local AES-256 Vaults
     • Kate-Huang-Goldberg AVSS       • Kate-Huang-Goldberg AVSS       • Kate-Huang-Goldberg AVSS
     • Leader-Based HybridDKG         • Leader-Based HybridDKG         • Leader-Based HybridDKG
```

---

## 3. Cryptographic Parameters & Quorums

SARAL implements the bivariate Asynchronous Verifiable Secret Sharing (AVSS) and leader-based HybridDKG protocols formalized by Kate, Huang, and Goldberg (ACNS 2012 / ePrint 2012/377).

| Parameter | Notation | Formula / Rule | Default ($n=5$) | Explanation |
| :--- | :---: | :--- | :---: | :--- |
| **Committee Size** | $n$ | Configured via `.env` | $5$ per domain | Total participating nodes per sovereign domain |
| **Reconstruction Threshold** | $k$ | Configured via `.env` | $3$ | Minimum shares needed to reconstruct secret |
| **Byzantine Malicious Bound** | $t$ | $n \ge 3t + 1$ | $1$ | Maximum tolerated Byzantine adversarial nodes |
| **Crash Fault Bound** | $f$ | $n \ge 3t + 2f + 1$ | $0$ | Crash-stop failure allowance |
| **Echo Quorum** | $Q_{\text{echo}}$ | $\lceil (n + t + 1) / 2 \rceil$ | $4$ | Required ECHOs to emit READY |
| **Ready Step Quorum** | $Q_{\text{ready-step}}$ | $t + 1$ | $2$ | Amplification threshold to emit READY |
| **Completion Quorum** | $Q_{\text{complete}}$ | $2t + f + 1$ | $3$ | Required READYs to finalize sharing |

> [!NOTE]
> **Liveness Notice:** Dual-threshold echo quorum formulas ($Q_{\text{dual}} = \lceil (n + k + t + 1) / 2 \rceil = 5$) deadlock if even 1 node crashes ($4 < 5$). SARAL implements the paper's proven quorum $Q_{\text{echo}} = 4$, guaranteeing 100% liveness when 1 node crashes while maintaining $k=3$ reconstruction safety.

---

## 4. Wallet Lifecycle Flow

### A. New User Registration (First-Time Onboarding)
```text
User ───► POST /api/wallet/generate
             │
             ├── 1. Auth Server generates 6 session IDs (3 domains x 2 curves).
             ├── 2. Auth Server issues concurrent saral_startDkg RPCs to all 3 Coordinators.
             ├── 3. 15 Go Nodes execute HybridVSS + Leader-Based HybridDKG.
             ├── 4. Each node combines its shares in RAM: x_j = sum(s_ij), Y = sum(V_i,0).
             ├── 5. Coordinators return verified domain public points: Y_F, Y_P, Y_R.
             ├── 6. Auth Server adds points in RAM: Y = Y_F + Y_P + Y_R.
             ├── 7. Auth Server derives MST, Solana, and Bitcoin addresses in RAM.
             └── 8. DB saves status='READY' with opaque key references (ZERO addresses/keys saved).
```

### B. Returning User Login (Zero DKG Re-Derivation)
```text
User ───► GET /api/wallet (with valid MFA token)
             │
             ├── 1. Auth Server finds existing wallet (status='READY').
             ├── 2. NEVER runs a new DKG session!
             ├── 3. Queries Coordinators for public contributions using stored dkgSessionIds.
             ├── 4. Coordinators compute Lagrange interpolation in exponent at x=0:
             │        Y_domain = sum( lambda_i * Y_i )
             ├── 5. Auth Server re-sums domain public points in RAM: Y = Y_F + Y_P + Y_R.
             ├── 6. Auth Server re-derives identical blockchain addresses in RAM.
             └── 7. Response returned to client (addresses exist only in volatile RAM).
```

---

## 5. Multi-Chain Native Support

| Network | Family | Curve | Derivation Algorithm | Address Format |
| :--- | :--- | :--- | :--- | :--- |
| **MST Testnet** | EVM | `secp256k1` | Keccak-256 of uncompressed $(x, y)$ + EIP-55 Checksum | `0x4b78...` (Mixed Case) |
| **Solana Devnet** | Solana | `ed25519` | 32-byte point compression + Base58 | `7dF3...` (Base58) |
| **Bitcoin Testnet** | Bitcoin | `secp256k1` | BIP-340/341 Taproot x-only public key + BIP-350 Bech32m | `tb1p...` (Witness v1) |

*BIP-340/341 Taproot Parity Invariant:* Points $(x, y)$ and $(x, -y \pmod p)$ share the identical $x$-coordinate and produce the identical Taproot address without private key exposure.

---

## 6. Environment Reference (`.env`)

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `NODE_ENV` | `development` | Runtime mode (`development`, `production`, `test`) |
| `PORT` | `3001` | Auth Server HTTP listening port |
| `DATABASE_URL` | `postgresql://saral:saral_secret@localhost:5432/saral` | Host database connection string |
| `DATABASE_URL_DOCKER` | `postgresql://saral:saral_secret@postgres:5432/saral` | Docker network database connection string |
| `COORDINATOR_URL` | `http://localhost:9001` | Default coordinator URL (Foundation) |
| `FOUNDATION_COORDINATOR_URL` | `http://localhost:9001` | Foundation Domain Coordinator RPC endpoint |
| `PUBLIC_COORDINATOR_URL` | `http://localhost:9002` | Public Domain Coordinator RPC endpoint |
| `PRIVATE_COORDINATOR_URL` | `http://localhost:9003` | Private Domain Coordinator RPC endpoint |
| `SARAL_FOUNDATION_NODES` | `5` | Total nodes in Foundation committee |
| `SARAL_PUBLIC_NODES` | `5` | Total nodes in Public committee |
| `SARAL_PRIVATE_NODES` | `5` | Total nodes in Private committee |
| `SARAL_FOUNDATION_THRESHOLD` | `3` | Threshold $k$ for Foundation committee |
| `SARAL_PUBLIC_THRESHOLD` | `3` | Threshold $k$ for Public committee |
| `SARAL_PRIVATE_THRESHOLD` | `3` | Threshold $k$ for Private committee |
| `SARAL_FAULTS_T` | `1` | Fault tolerance bound $t$ (Byzantine faults) |
| `SARAL_CRASH_F` | `0` | Crash fault bound $f$ |
| `SARAL_DKG_TIMEOUT_MS` | `15000` | Auth Server timeout awaiting 3-domain DKG consensus |
| `SARAL_HYBRID_DKG_TIMEOUT_MS` | `4000` | Node leader proposal timeout before triggering leader change |
| `SARAL_HYBRID_DKG_COLLECT_MS` | `150` | Node delay gathering validity certificates before proposing |
| `SARAL_INTERNAL_TOKEN` | `[min 32 chars]` | Cluster internal bearer token for inter-service RPC |
| `MFA_ENCRYPTION_KEY` | `[min 32 chars]` | AES-256 key for encrypting user TOTP secrets in database |
| `JWT_SECRET` | `[min 32 chars]` | Symmetric fallback secret for session tokens |
| `VAULT_DIR` | `/vault` | Path to node AES-256-GCM encrypted share vault |

---

## 7. Quick Start & Setup Commands

### Prerequisites
- Go 1.23+
- Node.js 20+ & npm 10+
- Docker & Docker Compose v2+
- OpenSSL & PostgreSQL 16 (optional if using Docker)

### 1. Wipe & Clean All
```bash
bash scripts/clean-all.sh
```

### 2. Automated Fresh Setup
```bash
bash scripts/fresh-setup.sh
```
This script compiles Go binaries, prepares cluster keys, sets up database tables, launches the 21 backend containers, verifies health, and validates genuine 3-domain multi-curve DKG consensus.

### 3. Start Local Development
```bash
# Start backend containers in Docker
npm run docker:nodes

# Run Auth Server and React Web Frontend concurrently
npm run dev
```
- Web UI: [http://localhost:5173](http://localhost:5173)
- Auth Server: [http://localhost:3001](http://localhost:3001)

---

## 8. Verification & Testing

```bash
# Run all test suites
npm test

# Run individual test suites:
npm run test:ts             # 53 TypeScript architecture & security tests (Vitest)
npm run test:go             # 13 Go architecture, relay, and symbol audit tests
npm run test:all-crypto     # Full cryptographic suite (finite fields, AVSS, DKG, integration)

# Run proof test suite (HybridDKG leader path, leader change, Byzantine dealer, fail-closed, invariance):
cd services/saral-node && go test -tags test_only -v -run "TestProof" ./dkg/...

# End-to-end verification script:
bash scripts/verify-all.sh
```

---

## 9. Honest Known Limitations

1. **Proactive Common Coin Simulation:** The proactive secret refresh package includes a deterministic pseudo-random common coin generator for test automation. In an asynchronous Byzantine production network, an asynchronous threshold PRF or BLS threshold signature scheme is required.
2. **Threshold Signing Milestone:** The current release focuses on dealerless key generation, multi-domain point combination, and deterministic multi-chain address derivation. Distributed threshold signing (FROST / MuSig2 / threshold EdDSA) is scheduled for the subsequent protocol phase.
3. **Google OAuth Secret Rotation:** The template credentials in `.env.example` are sanitized placeholders. Production deployments must configure real OAuth client credentials from Google Cloud Console.
