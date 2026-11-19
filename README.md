# SARAL Protocol — Distributed Key Generation & Web3 Wallet Architecture

A production-grade, architecture-first implementation of the **SARAL Protocol** (Separation-of-Powers Cryptographic Key Infrastructure).

SARAL distributes network trust, identity, and control-plane orchestration across three independent administrative realms: **Foundation Domain**, **Public Domain**, and **Private Domain**, ensuring private signing keys are never materialized in whole on any single server, database, or client device.

For complete cryptographic specifications, sequence diagrams, and mathematical formulations, see [SARAL_ARCHITECTURE.md](file:///home/mongoose/Poc/saral-poc/SARAL_ARCHITECTURE.md).

---

## 1. Key Invariants & Features

1. **Prisma ORM & PostgreSQL Persistence:**
   - Central authentication, policy, and wallet metadata managed via Prisma ORM (`apps/auth-server/prisma`).
   - Version-controlled schema migrations with strict relation and constraint integrity.
   - Singleton client lifecycle with connection pooling and graceful shutdown.
2. **Mandatory TOTP MFA (RFC 6238):**
   - Pure Node.js crypto implementation of RFC 6238 Time-Based One-Time Password.
   - Initial enrollment generates QR code, secret key, and 8 single-use backup recovery codes (`XXXX-XXXX`).
   - Secrets encrypted at rest using AES-256-GCM (`totp_secret_encrypted`).
   - Returning users challenged with TOTP without repeating enrollment.
3. **Authoritative Working Policy Engine:**
   - Enforced immediately post-MFA and evaluated on sensitive operations.
   - Time window checks with overnight span support using authoritative server time in IANA timezones.
   - Weekday validation (MON-SUN).
   - Haversine distance geofencing with fail-closed security.
4. **Zero-Address Persistence Mandate:**
   - Central PostgreSQL persists ZERO wallet addresses and ZERO signing private keys.
   - Persists only opaque key references (`key-mst-...`, `key-sol-...`, `key-btc-...`).
   - Addresses derived deterministically in RAM upon authenticated requests.
5. **Single Logical Wallet Invariant:**
   - Exactly one wallet per user (`UNIQUE(user_id)`).
   - Repeat logins idempotently recompute the exact same addresses without initiating redundant DKGs:
     `MST_Login1 == MST_Login2`, `SOL_Login1 == SOL_Login2`, `BTC_Login1 == BTC_Login2`.
6. **Chain-Compatible Address Derivations:**
   - **MST Testnet (EVM):** EIP-55 checksummed `0x...` hex address.
   - **Solana Devnet:** Base58 Ed25519 public key.
   - **Bitcoin Testnet:** BIP-340/341 Taproot $X$-only point with BIP-350 Bech32m using `tb1p...` prefix.
7. **Docker-Only Persistence (24-Container Mesh):**
   - Exactly 24 containers defined in `infra/compose/full24.yml`:
     1 `postgres` + 1 `auth-server` + 3 `verifiers` + 15 `nodes` + 3 `coordinators` + 1 `web`.
   - Central persistence in named volume `saral_postgres_data`.
   - Node shares in isolated named volumes `node_f1_vault` through `node_r5_vault`.

---

## 2. Prerequisites

- **Go:** `1.24+` (or `1.27+`)
- **Node.js:** `20.x` or `22.x+` (or `26.x`)
- **Docker & Docker Compose:** Docker Compose v2+
- **Git**

---

## 3. Quick Start Commands

### Method A: Full 24-Container Docker Mesh (Production Mode)

```bash
# 1. Clean build outputs
npm run clean

# 2. Build Go binaries, Prisma Client, TypeScript SDK, and Frontend
npm run build

# 3. Start the full 24-container mesh in Docker
docker compose -f infra/compose/full24.yml up -d --build

# 4. Check container health status (24 containers)
docker compose -f infra/compose/full24.yml ps

# 5. Stop Docker containers
docker compose -f infra/compose/full24.yml down

# 6. Stop and wipe all database & vault volumes (Complete Reset)
docker compose -f infra/compose/full24.yml down -v
```

### Method B: Local Development Mode (Auth Server + Web Frontend)

```bash
# 1. Install dependencies
npm install

# 2. Generate Prisma Client
npm run prisma:generate

# 3. Start development servers concurrently (Auth: 3001, Web: 5173)
npm run dev
```

* **Frontend UI:** [http://localhost:5173](http://localhost:5173) (Local Dev) or [http://localhost:3000](http://localhost:3000) (Docker)
* **Auth Server Health:** [http://localhost:3001/health](http://localhost:3001/health)

---

## 4. Prisma ORM & Database Migration

```bash
# Generate Prisma Client
npm run prisma:generate

# Deploy pending migrations
npm run prisma:migrate

# Open Prisma Studio (visual database inspector)
cd apps/auth-server && npx prisma studio
```

---

## 5. Running Verification & Test Suites

```bash
# 1. Run all unit and integration tests (SDK, Prisma, Architecture, Crypto)
npm test

# 2. Run TypeScript & SDK architecture tests
npm run test:sdk

# 3. Run Go 15-node distributed architecture tests
npm run test:go

# 4. Run full cryptography test suite (secp256k1, Ed25519, AVSS, Proactive, DKG)
npm run test:all-crypto
```

---

## 6. Project Structure

```text
saral-poc/
├── apps/
│   ├── web/               # React 19 + Vite + Tailwind CSS Web3 Wallet Frontend
│   └── auth-server/       # Node.js Auth Server (Prisma ORM, RS256 JWT, RFC 6238 MFA, Working Policy)
│       ├── prisma/        # Prisma Schema & Versioned Migrations
│       └── src/
│           ├── config/    # Centralized Environment & Auth Configuration
│           ├── database/  # Singleton Prisma Client & Connection Lifecycle
│           ├── middleware/# Authenticate (JWT RS256), RequireMfa, Policy & Error Handlers
│           ├── modules/   # Domain-Driven Modules (Auth, OTP, MFA, Policy, Wallet)
│           ├── utils/     # Cryptographic Primitives (EIP-55, Base58, Bech32m, TOTP)
│           ├── app.ts     # Express Application Config
│           └── server.ts  # Server Startup & Graceful Shutdown
├── packages/
│   └── saral-sdk/         # Typed JSON-RPC 2.0 Client SDK
├── services/
│   ├── coordinator/       # Go Coordinator (Foundation, Public, Private)
│   ├── verifier/          # Go Stateless Verifier (Token validation)
│   └── saral-node/        # Reusable Go Node daemon (P2P Mesh + AES-256-GCM Vaults)
├── infra/
│   ├── compose/
│   │   ├── full24.yml     # Complete 24-Container Production Mesh (PostgreSQL + Mesh)
│   │   └── poc15.yml      # 15-Node POC Compose configuration
│   ├── postgres/          # PostgreSQL initialization and schema
│   └── config/            # Genesis configurations
├── tests/
│   ├── architecture/      # End-to-end architecture, Prisma ORM, & SDK test suites
│   ├── avss/              # Asynchronous Verifiable Secret Sharing tests
│   ├── cryptography/      # Mathematical curve and finite field tests
│   ├── dkg/               # Distributed Key Generation protocol tests
│   ├── integration/       # Multi-chain integration tests
│   └── proactive/         # Proactive share refresh and consensus tests
├── README.md              # Project overview and runbook
└── SARAL_ARCHITECTURE.md  # Detailed architecture, threat model, and specifications
```

---

## 7. Troubleshooting

* **`failed to bind host port for 0.0.0.0:5432: address already in use`**:
  A local PostgreSQL instance is running on your host machine. Run `sudo systemctl stop postgresql` before running Docker Compose, or point `DATABASE_URL` in `.env` to your local host instance.
* **Database Reset**:
  To reset PostgreSQL and local node vaults to a clean state, run:
  ```bash
  docker compose -f infra/compose/full24.yml down -v
  ```
