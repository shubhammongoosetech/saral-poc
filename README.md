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

### 3.1 Recommended Workflow: Local Dev + Docker DKG Mesh
This is the recommended workflow for development: DKG nodes, coordinators, and verifiers run inside Docker, while Auth Server and Web Frontend run locally on the host for rapid live-reloading.

#### Step 1: Start Background DKG Mesh (Coordinators, Nodes, Verifiers)
Start the 21 DKG backend containers in Docker:
```bash
docker start $(docker ps -a -q --filter "name=saral-prod-coord" --filter "name=saral-prod-node" --filter "name=saral-prod-verifier")
```
*Verify containers are up and healthy:*
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

#### Step 2: Database Schema Sync (PostgreSQL)
Ensure your local PostgreSQL schema is in sync with Prisma:
```bash
cd apps/auth-server && npx prisma db push && cd ../..
```

#### Step 3: Run Application (Auth Server + Web Frontend)
Start both development servers concurrently:
```bash
npm run dev
```
* **Web Frontend:** [http://localhost:5173](http://localhost:5173)
* **Auth Server:** [http://localhost:3001](http://localhost:3001) (Health: [http://localhost:3001/health](http://localhost:3001/health))

---

### 3.2 Running Services Individually
If you want to run the frontend and backend in separate terminal windows:

* **Terminal 1 (Auth Server):**
  ```bash
  npm --prefix apps/auth-server run dev
  ```

* **Terminal 2 (Web Frontend):**
  ```bash
  npm --prefix apps/web run dev
  ```

---

### 3.3 Full 24-Container Docker Mesh (Production Mode)
Run everything (including PostgreSQL, Auth Server, and NGINX Web) inside Docker:

```bash
# 1. Clean build outputs
npm run clean

# 2. Build Go binaries, Prisma Client, TypeScript SDK, and Frontend
npm run build

# 3. Start all 24 containers in Docker
docker compose -f infra/compose/full24.yml up -d --build

# 4. Check status of all containers
docker compose -f infra/compose/full24.yml ps

# 5. Stop all Docker containers
docker compose -f infra/compose/full24.yml down

# 6. Stop and wipe all database & vault volumes (Complete Reset)
docker compose -f infra/compose/full24.yml down -v
```

---

## 4. Docker & Container Management Cheatsheet

### Start & Stop SARAL Containers
* **Start DKG Services Only (Nodes, Coordinators, Verifiers):**
  ```bash
  docker start $(docker ps -a -q --filter "name=saral-prod-coord" --filter "name=saral-prod-node" --filter "name=saral-prod-verifier")
  ```
* **Stop all SARAL containers (Safe - leaves other projects untouched):**
  ```bash
  docker stop $(docker ps -q --filter "name=saral")
  ```
* **Remove / Delete all SARAL containers (Safe):**
  ```bash
  docker rm $(docker ps -a -q --filter "name=saral")
  ```
* **Stop & Down via Docker Compose (and wipe data volumes):**
  ```bash
  npm run docker:down
  # or complete reset with volumes:
  docker compose -f infra/compose/full24.yml down -v
  ```

### Stop & Remove ALL Containers on Machine (Complete Clean)
> ⚠️ **Caution:** This will stop and remove containers from other projects as well (e.g., portainer, redis).
* **Stop ALL running containers:**
  ```bash
  docker stop $(docker ps -q)
  ```
* **Remove ALL containers:**
  ```bash
  docker rm $(docker ps -a -q)
  ```
* **Force Stop & Remove ALL in one command:**
  ```bash
  docker rm -f $(docker ps -a -q)
  ```

### Inspecting Logs & Node Vaults
* **Follow Coordinator logs:**
  ```bash
  docker logs -f saral-prod-coord-foundation
  ```
* **Follow Node logs:**
  ```bash
  docker logs -f saral-prod-node-f1
  ```
* **Inspect Key Shares inside a Node's Vault:**
  ```bash
  docker exec -it saral-prod-node-f1 ls -la /vault
  ```

---

## 5. Prisma ORM & Database Migration

```bash
# Generate Prisma Client
npm run prisma:generate

# Deploy pending migrations
npm run prisma:migrate

# Sync schema directly to database
cd apps/auth-server && npx prisma db push

# Open Prisma Studio (visual database inspector)
cd apps/auth-server && npx prisma studio
```

---

## 6. Running Verification & Test Suites

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

## 7. Project Structure

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

## 8. Troubleshooting

* **`failed to bind host port for 0.0.0.0:5432: address already in use`**:
  A local PostgreSQL instance is running on your host machine. Run `sudo systemctl stop postgresql` before running Docker Compose, or point `DATABASE_URL` in `.env` to your local host instance.
* **Database Reset**:
  To reset PostgreSQL and local node vaults to a clean state, run:
  ```bash
  docker compose -f infra/compose/full24.yml down -v
  ```
