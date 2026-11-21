# SARAL Protocol — Separation-of-Powers Cryptographic Key Infrastructure

A production-grade, dealerless threshold cryptography Web3 wallet platform and distributed microservice mesh.

SARAL distributes network trust, identity, and control-plane orchestration across three independent sovereign realms: **Foundation Domain**, **Public Domain**, and **Private Domain**. Private signing keys are never created, assembled, or persisted on any single server, database, or client device.

For complete mathematical formulations, cryptographic proofs, and protocol specifications, see [SARAL_ARCHITECTURE.md](file:///home/mongoose/Poc/saral-poc/SARAL_ARCHITECTURE.md).

---

## 1. Project Overview

SARAL eliminates both the custodial risk of central database key storage and the self-custody risk of vulnerable seed phrases.

### Core Architectural Invariants:
1. **Dealerless Distributed Key Generation (DKG):** Distributed 3-of-5 threshold keys generated collaboratively across independent Go nodes using Kate-Huang-Goldberg Asynchronous Verifiable Secret Sharing (AVSS) and Randomized Byzantine Agreement.
2. **Zero Central Key & Address Persistence:** The central PostgreSQL database persists **ZERO private keys, ZERO public keys, and ZERO blockchain addresses**. It stores only opaque key references (`key-mst-...`). Addresses are derived on-the-fly strictly in RAM upon authenticated requests.
3. **Strict One-User-One-Wallet Guarantee:** Exactly one logical multi-chain wallet per user (`UNIQUE(user_id)`). Returning users idempotently derive the exact same blockchain addresses without re-running DKG.
4. **Multi-Chain Native Compatibility:** Real aggregate public key points derive standard addresses for **MST Testnet (EVM EIP-55)**, **Solana Devnet (Ed25519 Base58)**, and **Bitcoin Testnet (BIP-341 Taproot Bech32m)**.
5. **Mandatory TOTP MFA & Working Policy:** Two-factor authentication (RFC 6238 TOTP) combined with an authoritative time and Haversine distance geofence engine.

---

## 2. Architecture

```text
React Web Frontend (Port 5173 / Port 80)
       │
       │ HTTP / REST (JWT Bearer)
       ▼
Node.js Auth Server (Port 3001) ───► PostgreSQL 16 (Port 5432)
       │                              (Opaque Key References Only)
       │ Scoped Ed25519 Tokens / JSON-RPC
       ▼
Go Coordinators (Foundation 9001, Public 9002, Private 9003)
       │
       │ Mutual TLS (mTLS 1.3) Mesh
       ▼
15 Distributed Go Nodes (5 Foundation, 5 Public, 5 Private)
  • Local Encrypted Vaults (/vault, AES-256-GCM)
  • Autonomous Kate-Huang-Goldberg AVSS Engine
  • Randomized Byzantine Agreement (ABBA)
```

---

## 3. Technology Stack

- **Frontend:** React 18, Vite, TypeScript, Tailwind CSS, TanStack Query, Radix UI.
- **Backend / Auth Server:** Node.js 20+, TypeScript, Express, Prisma ORM, PostgreSQL 16.
- **Distributed Microservices:** Go 1.24+ (Coordinator, Verifier, Saral-Node).
- **Cryptography:**
  - Secp256k1 & Ed25519 Elliptic Curves
  - Kate-Huang-Goldberg Bivariate AVSS
  - Pedersen Bivariate Commitments
  - Pure Keccak-256 with EIP-55 mixed-case checksum
  - Base58 encoding for Solana
  - BIP-341 Taproot key-tweak with BIP-350 Bech32m witness v1 encoding
  - AES-256-GCM for encrypted share vaults
- **Container Infrastructure:** Docker, Docker Compose (24-container self-contained mesh), Alpine Linux.

---

## 4. Folder Structure

```text
saral-poc/
├── apps/
│   ├── web/                     # React 18 + Vite + Tailwind CSS Web3 Dashboard
│   └── auth-server/             # Node.js Auth Server (Prisma ORM, EdDSA JWKS, MFA, Policy)
│       ├── prisma/              # Prisma schema & version-controlled migrations
│       └── src/
│           ├── auth/            # Asymmetric Ed25519 token manager & JWKS
│           ├── clients/         # Go Coordinator JSON-RPC client
│           ├── config/          # Centralized environment & auth config
│           ├── database/        # Singleton PrismaClient connection lifecycle
│           ├── middleware/      # authGuard, requireMfa, policyGuard, errorHandler
│           ├── routes/          # Express REST routes (auth.ts, wallet.ts)
│           ├── services/        # accountService, walletService, policyService, chainService
│           ├── storage/         # Unified in-memory cache with async Prisma synchronization
│           └── utils/           # EIP-55, Base58, Bech32m, TOTP cryptographic utilities
├── services/
│   ├── coordinator/             # Go Consensus Coordinator (Foundation, Public, Private)
│   ├── verifier/                # Go Stateless JWT / Proof Verifier
│   └── saral-node/              # Go MPC Node (AVSS, ABBA Consensus, Encrypted Vaults)
├── infra/
│   ├── compose/
│   │   ├── full24.yml           # Complete 24-container production mesh
│   │   └── poc15.yml            # 15-node development compose setup
│   ├── config/                  # Genesis registry & asymmetric Ed25519 public keys
│   ├── secrets/                 # Cluster secrets (internal tokens, admin keys)
│   ├── tls/                     # Cluster CA, certificates, and mTLS keys
│   └── postgres/                # PostgreSQL init SQL schema
├── scripts/
│   ├── clean-all.sh             # Safe cleanup & Docker volume wipe
│   ├── fresh-setup.sh           # Automated end-to-end stack build & bootstrap
│   ├── run-dev.sh               # Launch local development environment
│   ├── sync-genesis.js          # Sync container identities with genesis registry
│   └── verify-all.sh            # Run all verification test suites
├── tests/
│   ├── architecture/            # Architecture, Prisma ORM, and wallet lifecycle test suites
│   ├── avss/                    # AVSS cryptographic tests
│   ├── cryptography/            # Finite field and curve test vectors
│   ├── dkg/                     # Distributed Key Generation protocol tests
│   ├── integration/             # Multi-chain end-to-end integration tests
│   └── proactive/               # Proactive secret refresh tests
├── .env.example                 # Comprehensive environment configuration template
├── go.work                      # Go multi-module workspace
├── package.json                 # Monorepo workspaces configuration
├── README.md                    # Project overview & operator runbook
└── SARAL_ARCHITECTURE.md        # Detailed technical specifications
```

---

## 5. Prerequisites

- **Go:** `1.24+` installed on host
- **Node.js:** `20.x` or `22.x+` (Node 20+ required for native crypto & KaTeX)
- **npm:** `10.x+`
- **Docker & Docker Compose:** Docker v24+ with Docker Compose v2+
- **OpenSSL:** Standard Linux/macOS openssl utility

---

## 6. Environment Configuration

1. Copy the template to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Inspect `.env` and configure your environment (defaults work out of the box for local development).
3. **Never commit `.env` or files containing private credentials.**

---

## 7. Installation

Install all monorepo dependencies across the root and workspaces:

```bash
# Install Node.js dependencies across workspaces
npm install

# Compile all Go microservices (coordinator, verifier, saral-node)
npm run build:go

# Generate Prisma client & compile TypeScript apps
npm run build:apps
```

---

## 8. Development Run

### Recommended: Local Dev + Docker Background Mesh

This workflow runs the 21 Go backend containers in Docker while running the Auth Server and React Web UI on the host for rapid live-reloading:

```bash
# 1. Start background Go DKG mesh & PostgreSQL
npm run docker:nodes

# 2. Sync database schema (Zero-seed startup: initializes cleanly without demo users)
npm run prisma:migrate

# 3. Start Auth Server & Web Frontend concurrently
npm run dev
```

### Database Architecture & Zero-Seed Policy

The central PostgreSQL 16 database uses Prisma ORM (`apps/auth-server/prisma/schema.prisma`). All legacy demo tables (`transactions`), plaintext fields (`mfa.secret`, `mfa.recovery_codes`), and demo seed scripts (`seed.ts`) have been completely removed:

- **12 Active Tables:** `users`, `auth_identities`, `mfa` (encrypted), `mfa_recovery_codes` (hashed), `work_policy`, `otps`, `auth_sessions`, `wallets` (opaque refs only), `wallet_key_references`, `wallet_creation_jobs`, `security_event_logs`, and `access_logs`.
- **Zero Address & Key Storage:** PostgreSQL stores **ZERO private keys, ZERO public keys, and ZERO blockchain addresses**. Central storage holds only opaque identifiers (`key-mst-...`, `key-sol-...`, `key-btc-...`, `dkgSessionId`).
- **Live On-Chain Transactions:** The obsolete `transactions` table has been dropped; multi-chain activity is queried live from RPC endpoints (`chainService.ts`).
- **Zero-Seed Startup:** No demo accounts, mock wallets, or seed scripts are required. The stack initializes cleanly on an empty database and dynamically provisions users and wallets upon authenticated Google or phone login via Go Coordinator DKG.

- **Web Frontend:** [http://localhost:5173](http://localhost:5173)
- **Auth Server:** [http://localhost:3001](http://localhost:3001) (Health: [http://localhost:3001/health](http://localhost:3001/health))

---

## 9. Full Docker Run (Production Mesh)

Run the entire 24-container self-contained cluster inside Docker:

```bash
# 1. Build and start all 24 containers
docker compose -f infra/compose/full24.yml up -d --build

# 2. Check cluster health
docker compose -f infra/compose/full24.yml ps

# 3. Stop containers
docker compose -f infra/compose/full24.yml down

# 4. Stop and wipe persistent volumes (Complete clean reset)
docker compose -f infra/compose/full24.yml down -v
```

---

## 10. Authentication Flow

1. **Step 1 — Primary Authentication:**
   - Phone Login: `POST /api/auth/phone/request-otp` $\to$ `POST /api/auth/phone/verify-otp`.
   - Google Login: `POST /api/auth/google`.
   - Returns token with `mfaVerified: false`.
2. **Step 2 — Mandatory TOTP MFA (RFC 6238):**
   - New User: `POST /api/auth/mfa/enroll` (generates QR URI and 8 backup codes).
   - Verify: `POST /api/auth/mfa/verify` (validates code, returns upgraded token with `mfaVerified: true`).
3. **Step 3 — Working Policy Configuration:**
   - Set operating schedule and geofence: `PUT /api/wallet/policy`.
   - Policy is evaluated before any sensitive cryptographic operation.

---

## 11. Wallet Creation (First-Time User)

1. User clicks **"Create Wallet"** on the dashboard.
2. Web UI calls **`POST /api/wallet/generate`**.
3. Auth Server starts a 3-of-5 DKG session across the Foundation Nodes (`saral_startDkg`).
4. Nodes exchange bivariate polynomial commitments and reach Byzantine consensus.
5. Coordinator aggregates verified public points $Y = x \cdot G$.
6. Auth Server derives MST, Solana, and Bitcoin addresses in RAM.
7. Wallet metadata is saved in PostgreSQL as `status: 'READY'`. **Zero addresses and zero private keys are stored.**

---

## 12. Returning Wallet (Existing User)

1. User logs in and passes MFA.
2. Web UI loads `/wallet` and calls **`GET /api/wallet`**.
3. Auth Server verifies user already has a wallet (`status: 'READY'`). **No new DKG is initiated.**
4. Auth Server calls `saral_derivePublicKey` on the Go Coordinator.
5. 3 Foundation Nodes return their public points $Y_i = x_i \cdot G$.
6. Coordinator computes **Lagrange Interpolation at $x = 0$** in RAM:
   $$Y = \sum_{i=1}^{3} \lambda_i \cdot Y_i$$
7. Exact same Master Public Key $Y$ is recomputed, and addresses are derived on-the-fly.

---

## 13. Threshold & Quorum Specifications

- **Total Nodes:** $n = 5$ Foundation Nodes (`saral-foundation-1` through `5`).
- **Signing / Derivation Quorum:** $k = 3$ (At least 3 nodes required).
- **Byzantine Fault Tolerance:** $t = 1$ ($n > 3t \implies 5 > 3(1)$).
- **Security Guarantee:** Any single compromised node reveals zero information about the master key.

---

## 14. Multi-Chain Native Support

| Network | Family | Curve | Algorithm | Address Format |
| :--- | :--- | :--- | :--- | :--- |
| **MST Testnet** | EVM | Secp256k1 | Keccak-256 + EIP-55 | `0x4b78...` (Mixed Case) |
| **Solana Devnet** | Solana | Ed25519 | 32-byte Point Compression + Base58 | `7dF3...` (Base58) |
| **Bitcoin Testnet** | Bitcoin | Secp256k1 | BIP-341 Taproot Tweak + BIP-350 Bech32m | `tb1p...` (Witness v1) |

---

## 15. API Overview

All API endpoints are mounted on standard `/api` and root paths:

| Endpoint | Method | Purpose | Auth Required |
| :--- | :---: | :--- | :---: |
| `/api/auth/phone/request-otp` | `POST` | Request phone OTP | ❌ No |
| `/api/auth/phone/verify-otp` | `POST` | Verify phone OTP | ❌ No |
| `/api/auth/google` | `POST` | Verify Google ID token | ❌ No |
| `/api/auth/mfa/enroll` | `POST` | Enroll in TOTP MFA | ✅ Yes |
| `/api/auth/mfa/verify` | `POST` | Verify TOTP code & upgrade token | ✅ Yes |
| `/.well-known/jwks.json` | `GET` | Public Ed25519 JWKS key ring | ❌ No |
| `/api/wallet/generate` | `POST` | Create or get multi-chain wallet | ✅ Yes |
| `/api/wallet/create` | `POST` | Consolidated wallet creation API | ✅ Yes (MFA) |
| `/api/wallet` | `GET` | Get wallet addresses & live balances | ✅ Yes |
| `/api/wallet/balances` | `GET` | Read-only live balance refresh | ✅ Yes |
| `/api/wallet/transactions` | `GET` | Query inbound transactions | ✅ Yes |
| `/api/wallet/policy` | `GET/PUT` | Read or update working policy | ✅ Yes |

---

## 16. Testing

Run all test suites with a single command:

```bash
# Run all TypeScript, Go architecture, and cryptographic tests
npm test
```

### Individual Test Suites:

```bash
# 1. TypeScript security & wallet lifecycle suite (Vitest)
npm run test:ts

# 2. Go 15-node distributed architecture & relay network suite
npm run test:go

# 3. Multi-domain P2P relay integration suite
npm run test:relay

# 4. Cryptographic AVSS, ABBA consensus & proactive refresh suite
npm run test:all-crypto

# 5. Typecheck across all workspaces
npm run typecheck
```

---

## 17. Troubleshooting

### Port 5432 Already in Use:
A host PostgreSQL service is running. Either stop it (`sudo systemctl stop postgresql`) or point `DATABASE_URL` in `.env` to your host PostgreSQL.

### DKG Consensus Timeout:
Ensure all 5 Foundation Node containers (`saral-prod-node-f1` to `f5`) are running:
```bash
docker ps --filter "name=saral-prod-node-f"
```

### Resetting Cluster State:
To wipe all container data and recreate keys from a clean slate:
```bash
bash scripts/clean-all.sh
bash scripts/fresh-setup.sh
```

---

## 18. Security Architecture

- **Encrypted Node Vaults:** Node key shares are encrypted at rest with AES-256-GCM.
- **Fail-Closed Principle:** If nodes or verifiers are unreachable, address derivation fails closed; mock keys or fake HMAC fallbacks are strictly rejected.
- **Mutual TLS (mTLS 1.3):** Direct peer connections between nodes enforce cryptographic identity verification.
- **Asymmetric JWT / JWKS:** Authenticated internal requests use Ed25519 signed tokens verified against public JWKS key sets.
