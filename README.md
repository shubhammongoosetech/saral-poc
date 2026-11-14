# SARAL — 3-Domain Multi-Party Computation (MPC) Multi-Chain Wallet

A production-grade, non-custodial cryptographic key management system and Web3 wallet implementing a **3-Domain Separation of Powers** architecture with **Genuine Threshold ECDSA (secp256k1)**, **Ed25519 Multi-Chain Derivation (Solana Devnet)**, **Distributed Key Generation (DKG)**, **Zero-Address & Zero-Key Database Storage**, and **Adaptive Zero-Trust Context Policies** (Working Hours, GPS Geofencing & Velocity Anomaly Detection).

Supports **EVM Chains** (MST Testnet, Polygon Amoy) and **Solana Devnet** via modular monorepo SDK packages (`@saral-sdk/core`, `@saral-sdk/node`, `@saral-sdk/react`).

---

## 📑 Table of Contents

1. [Key Architecture & Security Highlights](#1-key-architecture--security-highlights)
2. [Multi-Chain Support (EVM & Solana)](#2-multi-chain-support-evm--solana)
3. [Tech Stack](#3-tech-stack)
4. [Monorepo & Folder Structure](#4-monorepo--folder-structure)
5. [Prerequisites](#5-prerequisites)
6. [Quick Start & Setup Instructions](#6-quick-start--setup-instructions)
7. [27-Node Docker Cluster Orchestration](#7-27-node-docker-cluster-orchestration)
8. [CLI Commands Reference](#8-cli-commands-reference)
9. [Environment Variables Reference](#9-environment-variables-reference)
10. [Database Schema & Prisma](#10-database-schema--prisma)
11. [End-to-End User & Security Workflow](#11-end-to-end-user--security-workflow)
12. [API Endpoints Reference](#12-api-endpoints-reference)
13. [SARAL SDK Packages (@saral-sdk/*)](#13-saral-sdk-packages-saral-sdk)
14. [Current Status & Verification](#14-current-status--verification)
15. [Troubleshooting & Common Issues](#15-troubleshooting--common-issues)

---

## 1. Key Architecture & Security Highlights

* **Zero Complete Private Key Reconstruction**:
  The complete master private key $x$ is **NEVER** materialized, formed, or reconstructed in any variable, buffer, process memory, or database table during key generation, address derivation, or transaction signing.
* **3-Domain Separation of Powers**:
  1. **Foundation Domain** (Institutional Administration): $t_F$-of-$n_F$ quorum (configured exclusively via `backend/.env`, default `9` nodes, threshold `5`).
  2. **Public Domain** (Decentralized Staking Quorum): $t_P$-of-$n_P$ quorum (default `9` nodes, threshold `5`).
  3. **Private Domain** (Sovereign User & Guardians): $t_U$-of-$n_U$ quorum (default `9` nodes, threshold `5`).
  All three domains are required simultaneously (`3-of-3 AND`) to authorize signing.
* **Single Source of Truth Dynamic Topology (`topologyConfig.ts`)**:
  Node counts and thresholds are configured solely via the six `SARAL_*` variables in `backend/.env` (minimum 3 nodes per domain, strict majority $t > n/2$, max 255). Total cluster size is computed dynamically ($N = N_F + N_P + N_V = 27$). Client overrides are strictly rejected by Zod schema validation.
* **Distributed Key Generation (DKG) without a Trusted Dealer**:
  Uses Feldman Verifiable Secret Sharing (VSS). Nodes independently generate secret polynomials, exchange verifiable sub-shares, and aggregate public commitments. The aggregated public key is derived via elliptic curve point addition:
  $$Q = Q_{\text{Foundation}} + Q_{\text{Public}} + Q_{\text{Private}}$$
  The EVM Ethereum address is computed from $Q$ (`ethers.computeAddress(Q)`).
* **Zero-Address & Zero-Key Database Storage (`sessionWalletRegistry.ts`)**:
  PostgreSQL stores **zero** private keys, **zero** plaintext secret shares, **zero** wallet addresses, and **zero** aggregated public keys (legacy `wallets` table was permanently purged). On login or server restart, the backend queries pinned nodes for public share points ($P_i = s_i \cdot G$), computes Lagrange interpolation in the exponent, and caches the derived address strictly in an ephemeral in-memory session map (`ACCESS_TOKEN_TTL_SECONDS`, default 15 minutes).
* **Multi-Tenant Encrypted Node Storage**:
  Key shares are encrypted with **AES-256-GCM** using domain-separated HKDF-SHA256 keys and stored across isolated node storage (dedicated Docker containers or filesystem vaults) pinned via Highest Random Weight (HRW) Rendezvous hashing in `wallet_placements`.
* **Zero-Trust Access Policies (`locationService.ts`)**:
  Access evaluation and transaction signing enforce MFA verification, original `loginMethod` matching, timezone-aware working hours, Haversine GPS geofencing (`radiusKm`, default `25 km`), and a 24-hour impossible-velocity check (`> 1,200 km/h` over `> 5 km`).

---

## 2. Multi-Chain Support (EVM & Solana)

SARAL natively supports multi-chain operations across different cryptographic curves:

| Network | Chain Type | Curve | Signature Scheme | Native Asset | RPC Endpoint |
|---|---|---|---|---|---|
| **MST Testnet** | EVM (Chain ID `91562037`) | secp256k1 | ECDSA (3-Domain MPC) | MSTC | `https://testnetrpc.mstblockchain.com` |
| **Polygon Amoy** | EVM (Chain ID `80002`) | secp256k1 | ECDSA (3-Domain MPC) | MATIC | `https://rpc-amoy.polygon.technology` |
| **Solana Devnet** | Non-EVM | Ed25519 | EdDSA | SOL | `https://api.devnet.solana.com` |

### Deterministic Cross-Curve Derivation
1. **EVM Public Key & Address**:
   Curve point addition $Q = Q_F + Q_P + Q_{Priv}$ on `secp256k1`, converted to 20-byte checksummed Ethereum address via Keccak-256 (`ethers.computeAddress(Q)`).
2. **Solana Public Key & Address**:
   The uncompressed bytes of $Q$ are hashed via HMAC-SHA256 with key `'SARAL_SOLANA_ED25519_KEY_SEED'` to derive a deterministic 32-byte Ed25519 seed (`Keypair.fromSeed(seed)`), producing a native Base58 Solana public address.
3. **UI Integration**:
   The frontend `SendForm` features a one-click **Network Selector** (MST Testnet, Polygon Amoy, Solana Devnet), real-time dual-balance display, dynamic network gas buffer reservation, and a "Max" send button.

---

## 3. Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, TypeScript, Vite 6, React Router DOM 6, Axios, Lucide Icons |
| **Backend** | Node.js (v26+), TypeScript, Express 5, Prisma ORM 6, `tsx`, Helmet, `express-rate-limit`, Zod 3/4 |
| **SDK Packages** | `@saral-sdk/core`, `@saral-sdk/node`, `@saral-sdk/react`, Vitest, Changesets |
| **Cryptography** | `@noble/curves` (secp256k1, ed25519), `ethers` v6, `@solana/web3.js`, `bs58`, Feldman VSS, Paillier MtA, AES-256-GCM, HKDF-SHA256 |
| **Database** | PostgreSQL 16 (Local or Docker container via `docker-compose.yml`) |
| **Authentication** | Google OAuth 2.0 (`google-auth-library`), Mobile SMS OTP, 2FA MFA, JWT (httpOnly cookies) |
| **Storage & Nodes** | 27 Isolated Docker containers (`saral-foundation-1..9`, `saral-public-1..9`, `saral-private-1..9`) |

---

## 4. Monorepo & Folder Structure

```text
saral-poc/
├── packages/                             # Modular SDK Monorepo Packages
│   ├── sdk-core/                         # Core types, DKG math, EVM/Solana adapters, policies
│   ├── sdk-node/                         # Node.js backend & CLI client for SARAL MPC
│   └── sdk-react/                        # React hooks (useSaralWallet, useSendTransaction) & UI
├── backend/
│   ├── config/                           # Topology definitions
│   ├── prisma/
│   │   └── schema.prisma                 # Prisma ORM schema & relations
│   ├── src/
│   │   ├── config/                       # env.ts, topologyConfig.ts, db.ts, chains.ts, swagger.ts
│   │   ├── controllers/                  # auth, mfa, profile, wallet, topology, activity
│   │   ├── crypto/                       # DKG, threshold ECDSA, mpcCoordinator, shamirField, secp256k1Math
│   │   ├── db/                           # schema.sql & SQL migrations
│   │   ├── middleware/                   # authGuard, cookieParser, csrf, errorHandler
│   │   ├── nodes/                        # nodeLauncher, dockerComposeGen
│   │   ├── participant/                  # MPC participant daemons, nodeIdentityManager
│   │   ├── routes/                       # auth, mfa, profile, wallet, topology, activity
│   │   ├── services/                     # authService, walletService, sessionWalletRegistry, locationService, chainService
│   │   ├── storage/                      # Hardened per-node encrypted FileStore
│   │   ├── topology/                     # HRW rendezvous placement, allocation, apply
│   │   ├── utils/                        # jwt, crypto, errors, logger, validation
│   │   ├── app.ts                        # Express app setup & middleware
│   │   └── server.ts                     # Server entry point
│   ├── .env.example
│   ├── package.json
│   └── tsconfig.json
├── frontend/
│   ├── src/
│   │   ├── api/                          # client.ts (Axios), endpoints.ts
│   │   ├── components/                   # Navbar.tsx, CopyButton.tsx
│   │   ├── hooks/                        # useAuth.tsx, useLocation.ts
│   │   ├── pages/
│   │   │   ├── Settings/                 # AccountSection, WorkingHoursSection, TopologySection
│   │   │   ├── Wallet/                   # WalletHeader, SendForm, TransactionList
│   │   │   ├── ActivityLog.tsx           # Audit logs & Security events
│   │   │   ├── Login.tsx                 # Google & SMS OTP login
│   │   │   ├── Mfa.tsx                   # 2FA challenge verification
│   │   │   ├── Review.tsx                # Policy confirmation gate
│   │   │   ├── Settings.tsx
│   │   │   ├── Wallet.tsx
│   │   │   └── WorkingPolicy.tsx         # Working hours & Geofencing setup
│   │   ├── types/                        # api.ts
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── .env.example
│   └── package.json
├── docs/                                 # Architectural specifications & audits
│   ├── AUDIT.md                          # Security verification audit
│   ├── DECISIONS.md                      # Architectural Decision Records (ADRs)
│   ├── PATENT_TRACE.md                   # Patent claim traceability matrix
│   ├── RUNBOOK.md                        # Production operations runbook
│   └── THREAT_MODEL.md                   # Threat modeling & attack vectors
├── docker-compose.yml                    # PostgreSQL 16 container service (host port 5433)
├── package.json                          # Root workspace runner scripts
└── README.md
```

---

## 5. Prerequisites

* **Node.js**: v26.0.0 or higher (`node -v`).
* **npm**: v11.0.0 or higher (`npm -v`).
* **PostgreSQL**: v14, v15, or v16 running locally or via Docker (`docker compose up -d postgres`).
* **Docker & Docker Compose**: For containerized 27-node cluster isolation.
* **Git** installed.

---

## 6. Quick Start & Setup Instructions

### Step 1: Install Dependencies Across All Workspaces

From the project root:
```bash
npm install
npm --prefix backend install
npm --prefix frontend install
npm run build:sdk
```

### Step 2: Configure Environment Variables

1. **Backend Configuration**:
   ```bash
   cp backend/.env.example backend/.env
   ```
   Key values in `backend/.env`:
   ```env
   PORT=3001
   NODE_ENV=development
   DATABASE_URL=postgresql://saral:saral_secret@localhost:5433/saral
   JWT_SECRET=your_super_secret_jwt_key_at_least_32_characters_long
   REFRESH_TOKEN_SECRET=your_super_secret_refresh_key_at_least_32_chars
   CSRF_SECRET=your_csrf_secret_min_16_characters
   FRONTEND_URL=http://localhost:5173
   RPC_URL=https://testnetrpc.mstblockchain.com
   CHAIN_ID=91562037

   # 3-Domain Node Topology Configuration (Single Source of Truth)
   SARAL_FOUNDATION_NODES=9
   SARAL_PUBLIC_NODES=9
   SARAL_PRIVATE_NODES=9
   SARAL_FOUNDATION_THRESHOLD=5
   SARAL_PUBLIC_THRESHOLD=5
   SARAL_PRIVATE_THRESHOLD=5
   ```

2. **Frontend Configuration**:
   ```bash
   cp frontend/.env.example frontend/.env
   ```
   In `frontend/.env`:
   ```env
   VITE_GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
   ```

### Step 3: Setup PostgreSQL Database

* **Using Docker (Recommended)**:
  ```bash
  docker compose up -d postgres
  ```
  *(Runs PostgreSQL 16 container `saral-poc-postgres` on port `5433`)*

* **Push Prisma Schema & Generate Client**:
  ```bash
  npm --prefix backend run db:generate
  npm --prefix backend run db:push
  ```

### Step 4: Launch Development Servers

```bash
npm run dev
```

* **Frontend App**: [http://localhost:5173](http://localhost:5173)
* **Backend API**: [http://localhost:3001](http://localhost:3001)
* **Swagger API Documentation**: [http://localhost:3001/docs](http://localhost:3001/docs)

---

## 7. 27-Node Docker Cluster Orchestration

SARAL runs 27 isolated node containers (9 Foundation + 9 Public + 9 Private) representing independent physical nodes with dedicated encrypted storage:

1. **Generate Docker Compose for 27 Nodes**:
   ```bash
   npm --prefix backend run docker:compose:gen
   ```
   *(Reads `backend/.env` topology and generates `backend/docker-compose.generated.yml`)*

2. **Start All 27 Nodes in Background**:
   ```bash
   docker compose -f backend/docker-compose.generated.yml up -d
   ```
   *(Spawns `saral-foundation-1..9`, `saral-public-1..9`, and `saral-private-1..9`)*

3. **Check Running Containers**:
   ```bash
   docker ps --filter "name=saral-"
   ```

4. **Stop Node Containers**:
   ```bash
   docker compose -f backend/docker-compose.generated.yml down
   ```

---

## 8. CLI Commands Reference

### Root Workspace Commands

| Command | Description |
|---|---|
| `npm run dev` | Runs backend (`localhost:3001`) and frontend (`localhost:5173`) concurrently |
| `npm run build` | Builds SDK packages, backend (`tsc`), and frontend (`vite build`) |
| `npm run build:sdk` | Builds all packages in `packages/*` using `tsup` |
| `npm test` | Runs backend unit tests and Vitest SDK test suite |
| `npm run test:sdk` | Runs Vitest tests on `@saral-sdk/*` (31 passing tests) |
| `npm run typecheck` | Type-checks backend, frontend, and all SDK packages |
| `npm run nodes:start` | Spawns background local MPC participant daemons |
| `npm run db:clear` | Safely wipes database test records |

### Backend Commands (`cd backend`)

| Command | Description |
|---|---|
| `npm run dev` | Starts backend in watch mode with `tsx` |
| `npm run build` | Compiles TypeScript to `dist/` |
| `npm run start:prod` | Runs compiled server (`node dist/server.js`) |
| `npm run db:generate` | Generates `@prisma/client` from `schema.prisma` |
| `npm run db:push` | Pushes schema directly to PostgreSQL database |
| `npm run db:studio` | Opens Prisma Studio GUI browser |
| `npm run docker:compose:gen` | Generates `docker-compose.generated.yml` for 27 nodes |

---

## 9. Environment Variables Reference

| Variable | Default Value | Description |
|---|---|---|
| `PORT` | `3001` | Express backend listening port |
| `NODE_ENV` | `development` | Environment mode (`development`, `test`, `production`) |
| `DATABASE_URL` | `postgresql://saral:saral_secret@localhost:5433/saral` | PostgreSQL connection string |
| `FRONTEND_URL` | `http://localhost:5173` | Allowed CORS origin |
| `JWT_SECRET` | `32+ chars` | Secret key for signing Access Tokens |
| `REFRESH_TOKEN_SECRET` | `32+ chars` | Secret key for signing Refresh Tokens |
| `CSRF_SECRET` | `16+ chars` | Secret key for CSRF token validation |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | In-memory session wallet & access token TTL (15 min) |
| `REFRESH_TOKEN_TTL_DAYS` | `7` | Refresh token cookie lifetime (7 days) |
| `RPC_URL` | `https://testnetrpc.mstblockchain.com` | Primary EVM RPC endpoint |
| `CHAIN_ID` | `91562037` | Primary EVM Chain ID (MST Testnet) |
| `TIME_TOLERANCE_MINUTES` | `0` | Grace window (minutes) around working hours |
| `LOCATION_RADIUS_KM` | `25` | Default geofence radius in kilometers |
| `SARAL_FOUNDATION_NODES` | `9` | Foundation domain node count (min `3`) |
| `SARAL_FOUNDATION_THRESHOLD` | `5` | Foundation quorum threshold (`> count / 2`) |
| `SARAL_PUBLIC_NODES` | `9` | Public domain node count (min `3`) |
| `SARAL_PUBLIC_THRESHOLD` | `5` | Public quorum threshold (`> count / 2`) |
| `SARAL_PRIVATE_NODES` | `9` | Private domain node count (min `3`) |
| `SARAL_PRIVATE_THRESHOLD` | `5` | Private quorum threshold (`> count / 2`) |

---

## 10. Database Schema & Prisma

PostgreSQL is managed strictly via Prisma ORM (`backend/prisma/schema.prisma`):

```mermaid
erDiagram
    users ||--o| mfa : has
    users ||--o| work_policy : defines
    users ||--o{ wallet_placements : pins
    users ||--o{ key_shares : references
    users ||--o{ access_logs : logs
    users ||--o{ security_event_logs : audits
    users ||--o{ transactions : executes
    users ||--o{ otps : verifies
```

* `users`: User identity (`google_id`, `email`, `mobile`, `login_method`).
* `mfa`: 2FA state (`type`, `secret`, `verified_at`).
* `work_policy`: Permitted working hours (`start_time`, `end_time`, `timezone`) and GPS geofence (`city`, `lat`, `lng`, `radius_km`).
* `wallet_placements`: Pinned Rendezvous (HRW) node IDs, per-domain thresholds, `epoch`, `manifest_hash`, and `protocol_version`.
* `key_shares`: **Zero-Key storage** — stores only `category`, `share_index`, `n`, `threshold`, `container_id`, and `container_name` (no private keys or ciphertext shares in DB).
* `transactions`: `tx_hash`, recipient `to_address`, `amount`, `status`, and timestamp.
* `access_logs`: Audit log of policy evaluations (`allowed`, `reason`, `lat`, `lng`, `attempted_at`).
* `security_event_logs`: Hash-chained security audit trail (`event_type`, `severity`, `details`, `previous_hash`, `entry_hash`).
* `otps`: HMAC-SHA256 hashed login/MFA OTP codes with expiration tracking.

---

## 11. End-to-End User & Security Workflow

### Step 1: Authentication (`/login`)
* **Google OAuth** or **Mobile SMS OTP**: Verifies credentials, issues initial JWT (`mfaVerified: false`), and returns profile status (`hasPolicy`, `hasWallet`).
* In development mode, mobile SMS OTP is logged to stdout (`[SMS OTP AUTH] ... | Code: xxxxxx`).

### Step 2: MFA Verification (`/mfa`)
* Dispatches a 6-digit OTP challenge, verifies it via `mfaService.ts`, and issues an upgraded JWT with **`mfaVerified: true`**.
* **First-time users (`hasPolicy === false`)**: Redirected to `/working-policy` $\to$ `/review` $\to$ `/wallet`.
* **Returning users (`hasPolicy === true`)**: Browser GPS coordinates are evaluated against the geofence; if valid, user is redirected directly to `/wallet`.

### Step 3: Working Policy & Review (`/working-policy`, `/review`)
* User sets working hours (e.g. `09:00`–`18:00`), timezone, city, and GPS coordinates (default `25 km` radius).
* Clicking **Confirm** validates current server time and location via `POST /api/wallet/check-access`.

### Step 4: Wallet Generation or Ephemeral Derivation (`/wallet`)
* **First-time user (`hasWallet === false`)**:
  Clicks **Create wallet** (`POST /api/wallet/generate`). The backend runs 3-Domain DKG:
  1. Generates 9 shares for Foundation, 9 for Public, and 9 for Private.
  2. Aggregates curve points: $Q = Q_F + Q_P + Q_U$.
  3. Derives EVM address (`0x...`) and Solana Base58 address (`9xQe...`).
  4. Encrypts all 27 shares with AES-256-GCM and deploys them to Docker nodes.
  5. Pins HRW placement in PostgreSQL.
* **Returning user (`hasWallet === true`)**:
  `sessionWalletRegistry.ts` queries pinned nodes for public share points ($s_i \cdot G$), interpolates in exponent to derive $Q$, and caches EVM/Solana addresses strictly in ephemeral RAM for 15 minutes. **Zero keys stored in database.**

### Step 5: Multi-Chain Threshold Signing (`POST /api/wallet/sign`)
* **Zero-Trust Gate Check (`evaluateAccessPolicy`)**:
  Validates MFA freshness, login method matching, server-side working hours in user's timezone, 24-hour velocity check, and Haversine GPS geofencing. `SendForm` automatically supplies browser coordinates (`lat`, `lng`).
* **Execution**:
  * **EVM (MST Testnet / Polygon Amoy)**: Interactive 3-domain MPC threshold signing (`mpcCoordinator.ts`). Broadcasts raw signed transaction to RPC.
  * **Solana Devnet**: Derives Ed25519 keypair, constructs Solana transfer transaction, and broadcasts to Solana Devnet RPC.

### Step 6: Settings & Activity (`/settings`, `/activity`)
* `/settings`: Manage account details, update working hours, and inspect 27-node cluster topology.
* `/activity`: Inspect tamper-proof **Hash-Chained Security Event Logs** where each log entry contains `previous_hash` and `entry_hash`.

---

## 12. API Endpoints Reference

Interactive Swagger documentation is available at **`http://localhost:3001/docs`**.

### Auth & MFA
* `POST /api/auth/google` — Google OAuth credential login
* `POST /api/auth/otp/request` — Request mobile SMS OTP
* `POST /api/auth/otp/verify` — Verify SMS OTP and issue session token
* `POST /api/mfa/send` — Dispatch 6-digit MFA OTP
* `POST /api/mfa/verify` — Verify MFA OTP and upgrade token to `mfaVerified: true`

### Profile & Policy
* `GET /api/profile` — Fetch user status (`mfaVerified`, `hasPolicy`, `hasWallet`) and policy
* `POST /api/profile/policy` — Save or update working hours and geofencing policy

### Wallet & Multi-Chain Operations
* `GET /api/wallet` — Retrieve active wallet metadata, EVM address, Solana address, and live balances
* `POST /api/wallet/generate` — Execute 3-Domain MPC DKG (strictly once per user)
* `POST /api/wallet/check-access` — Evaluate Zero-Trust policy gate (time and GPS geofence)
* `POST /api/wallet/sign` — Execute multi-chain transaction signing:
  * Payload: `{ toAddress, amount, chainOrId?: "mst-testnet" | "solana-devnet" | "polygon-amoy", lat, lng }`
* `GET /api/wallet/transactions` — Fetch transaction history
* `GET /api/wallet/cluster-health` — Real-time health status of 27 storage node containers

### Topology & Activity
* `GET /api/topology` — Active dynamic cluster topology
* `GET /api/topology/nodes` — List of all 27 nodes across Foundation, Public, and Private domains
* `GET /api/topology/placement` — User's pinned HRW node placement
* `GET /api/activity` — Paginated access logs and hash-chained security event audit trail

---

## 13. SARAL SDK Packages (@saral-sdk/*)

SARAL provides a modular monorepo SDK under `packages/` for client-side and server-side Web3 integrations:

### 1. `@saral-sdk/core` (`packages/sdk-core`)
Core cryptographic types, mathematical functions, multi-chain adapters, and policy interfaces:
* `EvmChainAdapter` & `SolanaChainAdapter`
* Feldman VSS verification & Lagrange interpolation utilities
* Cross-curve address derivation (`deriveSolanaAddress`, `deriveSolanaKeypair`)

### 2. `@saral-sdk/node` (`packages/sdk-node`)
Node.js client for backend servers, CLI tools, and automated pipelines:
```typescript
import { SaralClient } from '@saral-sdk/node';

const saral = new SaralClient({
  baseUrl: 'http://localhost:3001',
  accessToken: 'eyJhbGciOiJIUzI1Ni...',
});

const wallet = await saral.getWallet();
console.log('EVM Address:', wallet.address);
console.log('Solana Address:', wallet.solanaAddress);

const tx = await saral.sendTransaction({
  toAddress: '0x3F5b...',
  amount: '0.1',
  chainOrId: 'mst-testnet',
});
```

### 3. `@saral-sdk/react` (`packages/sdk-react`)
React hooks and context providers for Web3 frontend dApps:
```tsx
import { SaralProvider, useSaralWallet, useSendTransaction } from '@saral-sdk/react';

function MyDApp() {
  const { wallet, balance, solanaBalance, refresh } = useSaralWallet();
  const { send, isSending } = useSendTransaction();

  return (
    <div>
      <p>EVM: {wallet?.address} ({balance} MSTC)</p>
      <p>Solana: {wallet?.solanaAddress} ({solanaBalance} SOL)</p>
      <button onClick={() => send({ to: '0x...', amount: '0.01', chain: 'mst-testnet' })}>
        Send
      </button>
    </div>
  );
}
```

---

## 14. Current Status & Verification

* **Automated Test Suite**: 31 unit and integration tests across `@saral-sdk/*` pass cleanly with 0 errors (`npm test`).
* **Send Form Geolocation**: `SendForm.tsx` captures browser GPS coordinates via `getCurrentCoords()` and transmits them to `/api/wallet/sign`, fully satisfying the Zero-Trust policy gate.
* **Dual EVM & Solana Sync**: Live broadcast and balance polling are fully operational on both MST Testnet (EVM) and Solana Devnet.
* **Separation-of-Powers Cluster**: 27 Docker containers with dynamic Compose generation and encrypted volume persistence are fully supported.
* **Legacy Codebase Cleanup**: All legacy economic security, devices, guardians, and recovery dead code have been purged from the schema and codebase.

---

## 15. Troubleshooting & Common Issues

### 1. Wallet balance shows `0.0000 MSTC` on Refresh even when funded
* **Cause**: In `backend/src/services/chainService.ts`, `getBalance()` enforces a 4,000 ms RPC timeout and catches RPC network errors (such as intermittent 500 errors from testnet RPC), returning `'0.0000'` as a safe fallback.
* **Fix**: Click **Refresh** once the testnet RPC stabilizes, or update `RPC_URL` in `backend/.env` to another reliable EVM RPC node.

### 2. Database Connection Error (`localhost:5433` vs `5432`)
* **Fix**:
  * If using Docker Compose: start the container with `docker compose up -d postgres` and ensure `backend/.env` uses port `5433`:
    ```env
    DATABASE_URL=postgresql://saral:saral_secret@localhost:5433/saral
    ```
  * If using local PostgreSQL on host port `5432`: update `DATABASE_URL` in `backend/.env` to point to port `5432`.

### 3. Google Sign-In Error (`Audience Mismatch` or Error 500)
* **Fix**: Ensure `GOOGLE_CLIENT_ID` in `backend/.env` and `VITE_GOOGLE_CLIENT_ID` in `frontend/.env` match identically. Restart both backend and frontend servers.

### 4. Missing Development OTP
* **Fix**: Check backend terminal console. In `development` mode, login and MFA OTPs are printed to stdout (`[SMS OTP AUTH] ...` and `[MFA OTP CHALLENGE] ...`).

### 5. Resetting Database State
```bash
cd backend
npm run db:push
npm run db:clear
```

---

## 📄 License & Intellectual Property

SARAL POC architecture is developed in alignment with Separation of Powers Non-Custodial Key Management and Multi-Party Computation patent specifications. All rights reserved.
