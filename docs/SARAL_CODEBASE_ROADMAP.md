# SARAL Protocol — Complete Codebase Architecture & Learning Roadmap

This comprehensive technical guide details the entire **SARAL** protocol, distributed cryptographic architecture, codebase implementation, security invariants, and local runbook. It serves as an authoritative learning document and reference for the codebase on branch `saral-mohit-new`.

---

## 1. Executive Summary & Core Architectural Invariants

SARAL eliminates both the custodial risk of central database key storage and the self-custody risk of vulnerable seed phrases. Trust, cryptographic power, and control are distributed across a **15-node mesh** partitioned into **3 sovereign domains**:

```
                       ┌─────────────────────────────────────┐
                       │     SARAL Web UI (React 18)         │
                       └──────────────────┬──────────────────┘
                                          │ HTTP / REST
                                          ▼
                       ┌─────────────────────────────────────┐
                       │    Auth-Server (Node.js/Express)    │
                       └──────────┬──────────────────┬───────┘
                                  │                  │
                Scoped Ed25519    │                  │  Stores ONLY UUIDs:
                Tokens / JSON-RPC │                  │  • userId, walletId
                                  ▼                  ▼  • Session references
                       ┌────────────────────┐   ┌────────────────────────┐
                       │   Coordinator Mesh │   │   PostgreSQL Database  │
                       │   (Ports 9001-9003)│   │ (ZERO keys or addrs)   │
                       └──────────┬─────────┘   └────────────────────────┘
                                  │
                                  │ mTLS 1.3 / Mesh Protocol
                                  ▼
         ┌────────────────────────┼────────────────────────┐
         │                        │                        │
         ▼                        ▼                        ▼
 ┌───────────────┐        ┌───────────────┐        ┌───────────────┐
 │  Foundation   │        │    Public     │        │    Private    │
 │    Domain     │        │    Domain     │        │    Domain     │
 │ 5 Nodes (k=3) │        │ 5 Nodes (k=3) │        │ 5 Nodes (k=3) │
 └───────────────┘        └───────────────┘        └───────────────┘
```

### The 4 Irreducible Invariants of SARAL:

1. **Strict Zero-Persistence Invariant:**
   - **PostgreSQL and the Auth-Server persist ZERO private keys, ZERO master public keys, and ZERO blockchain addresses.**
   - The central database stores only non-sensitive metadata: `userId`, `walletId`, `policy`, and opaque session descriptors (`mesh: { domain: { chain: { keyId, sessionId } } }`).
   - Addresses are deterministically computed on-the-fly strictly in volatile RAM upon authenticated requests and never saved to disk in the central tier.

2. **Sovereign Three-Domain Separation of Powers:**
   - 15 total distributed Go nodes are split into 3 distinct domains: **Foundation** (nodes 1–5), **Public** (nodes 6–10), and **Private** (nodes 11–15).
   - Each domain independently enforces a $(k=3, n=5)$ threshold polynomial ($t=1$ Byzantine fault tolerance).
   - Compromising an entire domain (all 5 nodes) yields zero knowledge of the master private key or master public key.

3. **Stateless Returning-User Determinism:**
   - When a user logs out and logs back in, **NO new DKG sessions are initiated**.
   - Authenticated via asymmetric EdDSA JWKS tokens, $k=3$ nodes in each of the 3 domains evaluate their local shares at $x=0$ to return public point evaluations.
   - The Coordinator recombines the domain public points in RAM, adds them across domains, and deterministically re-derives the **exact same blockchain addresses and balances**.

4. **Multi-Chain Threshold Signature Scheme (TSS) without Key Assembly:**
   - Transactions are signed directly across the distributed nodes using threshold cryptography.
   - The master private key is **never reconstructed or unified in memory** on the client, Auth-Server, or Coordinator.

---

## 2. Cryptographic Foundations & Mathematical Formulations

SARAL supports 3 distinct blockchain environments, each requiring distinct elliptic curves and address encodings:

| Chain Target | Elliptic Curve | Standard & Derivation | Final Address Format |
| :--- | :--- | :--- | :--- |
| **MST Testnet** | secp256k1 | EVM Keccak-256 (last 20 bytes) + EIP-55 checksum | `0x` + 40 hex characters (mixed case) |
| **Solana Devnet** | Ed25519 | Base58 encoding of 32-byte Edwards point | 32–44 alphanumeric characters (Base58) |
| **Bitcoin Testnet** | secp256k1 | BIP-341 Taproot key tweak + BIP-350 Bech32m witness v1 | `tb1p` + Bech32m encoded characters |

### 2.1 Distributed Key Generation (DKG) & AVSS
- Uses **Kate-Huang-Goldberg Asynchronous Verifiable Secret Sharing (AVSS)** based on bivariate polynomials:
  $$F(x, y) = \sum_{i=0}^{t} \sum_{j=0}^{t} a_{i,j} x^i y^j \pmod q$$
  with symmetric bivariate commitments:
  $$C_{i,j} = g^{a_{i,j}} \in G$$
- In each domain, nodes independently deal shares and verify consistency via Pedersen commitments.
- Once randomized Byzantine agreement completes, node $i$ stores its evaluated share $s_i = F(i, 0)$ inside its local encrypted vault (`/vault`, encrypted with AES-256-GCM).

### 2.2 Domain Aggregation into Master Public Key
For each chain, the 3 independent domain public keys are aggregated additively on the curve:
$$P_{\text{master}} = P_{\text{foundation}} + P_{\text{public}} + P_{\text{private}}$$

Because each domain public key $P_d$ is reconstructed from $k=3$ Lagrange interpolation coefficients $\lambda_i$:
$$P_d = \sum_{i \in S_d} \lambda_i \cdot P_{d, i}$$
the full master public key $P_{\text{master}}$ is securely evaluated without any single party learning individual private shares.

### 2.3 Threshold Signatures (TSS)
- **MST Testnet (secp256k1 ECDSA):**
  Signatures $(r, s)$ enforce the **BIP-62 / EIP-2 low-S rule**:
  $$\text{if } s > \frac{n}{2} \implies s' = n - s$$
  preventing transaction malleability.
- **Solana Devnet (Ed25519 FROST):**
  Uses Schnorr-style distributed nonce commitments ($R$) and response scalars ($s$) conforming to RFC 9591.
- **Bitcoin Testnet (BIP-340 / BIP-341):**
  Uses Schnorr threshold signatures over the tweaked internal key $Q = P + h_{\text{tapTweak}}(P) \cdot G$.

---

## 3. End-to-End Workflow: Step-by-Step

### Step 1: User Authentication & Working Policy
1. **Login Options:**
   - **Google OAuth:** Asymmetric ID token verified against Google public keys.
   - **Developer OTP Mode:** For local testing, OTP is provided directly with 1-click auto-fill on the UI.
2. **Mandatory 2FA (TOTP):**
   - User verifies 6-digit TOTP code (`/api/mfa/verify`).
   - Auth-Server elevates the session with an EdDSA-signed JWT (`sessionToken`).
3. **Working Policy Engine:**
   - Verifies the user's allowed schedule (e.g., Monday–Friday, 09:00–18:00 UTC) and optional geofence boundary using the Haversine distance formula.

### Step 2: First-Time Wallet Generation (DKG Initiation)
1. Frontend calls `POST /api/wallet/generate`.
2. Auth-Server generates a unique `walletId` (UUID v4).
3. Auth-Server issues signed scoped requests to the 3 Domain Coordinators:
   - Foundation Coordinator (Port 9001)
   - Public Coordinator (Port 9002)
   - Private Coordinator (Port 9003)
4. Each Coordinator initiates 3 DKG sessions (one for MST, one for Solana, one for Bitcoin) across its 5 constituent nodes (total 9 DKG sessions across the 15 nodes).
5. Nodes complete AVSS, verify bivariate commitments, and store encrypted shares in local node vaults (`/vault`).
6. Each Coordinator returns its domain public key to the Auth-Server in RAM.
7. Auth-Server aggregates the domain keys, derives the 3 multi-chain addresses, and sends them to the frontend.
8. **Storage Check:** Central PostgreSQL stores ONLY the `walletId` and session references. Zero addresses, zero keys!

### Step 3: Returning User Login (Zero-DKG Deterministic Derivation)
1. User logs in from a new session or device.
2. Auth-Server finds existing `walletIdentity` containing session references.
3. Auth-Server requests public point evaluations at $x=0$ from the 3 Coordinators:
   - Coordinators query any $k=3$ available nodes in their domain.
   - Nodes authenticate the incoming request using the Auth-Server's public EdDSA JWKS.
   - Nodes return public polynomial point shares.
4. Coordinators reconstruct $P_{\text{foundation}}$, $P_{\text{public}}$, $P_{\text{private}}$ in RAM.
5. Auth-Server computes $P_{\text{master}}$ and derives the exact same addresses:
   - MST: `0x...`
   - Solana: `Base58...`
   - Bitcoin: `tb1p...`
6. Live balances and transaction activity are fetched from testnet RPCs and displayed on the dashboard.

### Step 4: Multi-Chain TSS Transaction Signing
1. User enters recipient address and amount in the `SendPanel` and clicks "Send".
2. Frontend calls `POST /api/wallet/sign`.
3. Working policy and MFA authentication are verified fail-closed.
4. Distributed nodes execute threshold signature rounds across domains without private key reconstruction.
5. Final broadcast transaction hash (`txHash`), signature components $(r, s, v)$, and block explorer links are returned and rendered.
6. Central database logs an immutable audit trail (`store.logAccess`) containing only the timestamp and authorization reason.

---

## 4. Codebase Directory Structure & Guided Reading Order

```
saral-poc/
├── apps/
│   ├── auth-server/                     # Node.js 20 + TypeScript + Express Backend
│   │   ├── prisma/
│   │   │   ├── schema.prisma            # Schema: Users, MFA, Policies, Wallet (zero-key)
│   │   │   └── migrations/              # Version-controlled SQL migrations
│   │   └── src/
│   │       ├── auth/                    # Asymmetric EdDSA token issuance & JWKS
│   │       ├── clients/                 # JSON-RPC client to Go Coordinators
│   │       ├── middleware/              # authenticate.ts, requireMfa.ts, errorHandler.ts
│   │       ├── routes/
│   │       │   ├── auth.ts              # Login, Google, and dev OTP routes
│   │       │   ├── mfa.ts               # TOTP enrollment & verification
│   │       │   └── wallet.ts            # Wallet generation, reading, and TSS signing
│   │       ├── services/
│   │       │   ├── walletService.ts     # Core wallet orchestration & TSS signing
│   │       │   ├── chainService.ts      # Multi-chain RPC balance & activity queries
│   │       │   └── policyService.ts     # Time & geofence authorization rules
│   │       └── utils/
│   │           ├── bech32m.ts           # Bitcoin BIP-350 Taproot witness encoding
│   │           ├── eip55.ts             # EVM Keccak-256 checksum encoder
│   │           └── secp256k1.ts         # Pure elliptic curve point operations
│   │
│   └── web/                             # React 18 + Vite + Tailwind CSS Frontend
│       └── src/
│           ├── app/guards/              # Route protection (Session, MFA, Policy gates)
│           ├── features/
│           │   ├── auth/                # LoginForm.tsx (dev OTP auto-fill), Mfa.tsx
│           │   ├── policy/              # WorkingPolicy.tsx, Review.tsx
│           │   └── wallet/              # Wallet.tsx, ReceivePanel.tsx, SendPanel.tsx
│           ├── services/                # walletApi.ts, authApi.ts, httpClient.ts
│           └── shared/ui/               # QrCode.tsx, Amount.tsx, ErrorBoundary.tsx
│
├── services/
│   ├── coordinator/                     # Go Coordinator Service (Ports 9001-9003)
│   │   └── internal/rpc/
│   │       ├── rpc.go                  # JSON-RPC dispatcher
│   │       ├── dkg.go                  # DKG initiation & coordination
│   │       └── wallet.go               # Deterministic address & TSS signing RPCs
│   │
│   └── saral-node/                      # 15 Distributed Go Nodes (Mesh participants)
│       ├── avss/                        # Kate-Huang-Goldberg bivariate AVSS engine
│       ├── cryptography/                # secp256k1, Ed25519, Pedersen commitments
│       ├── dkg/                         # Distributed Key Generation & consensus state
│       └── vault/                       # AES-256-GCM encrypted local share store
│
├── tests/
│   └── architecture/                    # Exhaustive security & integration test suite
│       ├── wallet_lifecycle_security.test.ts # 16 tests: DKG, determinism, zero persistence, TSS
│       ├── auth_policy_wallet.test.ts        # MFA & policy enforcement
│       └── prisma_integration.test.ts        # Database schema & constraint tests
│
└── docs/
    ├── SARAL-Code-Roadmap.pdf           # 6-page visual architecture roadmap
    └── SARAL_CODEBASE_ROADMAP.md        # This document
```

---

## 5. Local Setup & Verification Runbook (Windows PowerShell)

### Prerequisites:
- **Node.js**: v20+ (`node -v`)
- **Go**: 1.24+ (`go version`)
- **PostgreSQL**: 16+ running on `localhost:5432` (`saral:saral_secret`)
- **Docker**: (Optional, for full 24-container mesh simulation)

### 5.1 Environment Configuration
Verify root `.env` and `apps/auth-server/.env`:
```env
DATABASE_URL="postgresql://saral:saral_secret@localhost:5432/saral"
SARAL_JWT_SECRET="saral_jwt_secret_dev_key_32_bytes_min_ok!"
COORDINATOR_URL="http://localhost:9001"
DEV_OTP_EXPOSE=true
PORT=3001
```

### 5.2 Database Synchronization
```powershell
# Generate Prisma client and push schema
npx prisma db push --schema=apps/auth-server/prisma/schema.prisma
```

### 5.3 Run All Test Suites
Execute all test suites to confirm zero regressions:

```powershell
# 1. Run Vitest Architecture & Zero-Persistence Tests
npm run test:ts

# 2. Run Frontend Web Tests & Typecheck
npm --prefix apps/web run test
npm --prefix apps/web run typecheck

# 3. Run Backend Auth-Server Typecheck
npm --prefix apps/auth-server run typecheck

# 4. Run Go Coordinator, Node DKG, and Architecture Tests
go test ./services/coordinator/internal/rpc/...
go test ./services/saral-node/dkg/...
go test ./tests/architecture/...
```

### 5.4 Starting the Development Stack
```powershell
# Terminal 1: Auth Server (Backend)
npm --prefix apps/auth-server run dev

# Terminal 2: Web Dashboard (Frontend)
npm --prefix apps/web run dev
```
Navigate your browser to `http://localhost:5173`. Use the convenient 1-click dev OTP to sign in, enroll/verify your authenticator, configure your working policy, and interact with your multi-chain DKG/TSS wallet!
