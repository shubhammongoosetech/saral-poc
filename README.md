# SARAL — 3-Domain Multi-Party Computation (MPC) Wallet

A non-custodial cryptographic key management system and Web3 wallet implementing a **3-Domain Separation of Powers** architecture with **Genuine Threshold ECDSA (secp256k1)**, **Distributed Key Generation (DKG)**, **Zero-Address & Zero-Key Database Storage**, and **Adaptive Zero-Trust Context Policies** (Working Hours, Geofencing & Velocity Anomaly Detection).

Compatible with EVM chains and the **MST Testnet**.

---

## 📑 Table of Contents

1. [Key Architecture & Security Highlights](#1-key-architecture--security-highlights)
2. [Tech Stack](#2-tech-stack)
3. [Folder Structure](#3-folder-structure)
4. [Prerequisites](#4-prerequisites)
5. [Quick Start & Setup Instructions](#5-quick-start--setup-instructions)
6. [All Necessary CLI Commands](#6-all-necessary-cli-commands)
7. [Environment Variables Reference](#7-environment-variables-reference)
8. [Database Schema & Prisma](#8-database-schema--prisma)
9. [End-to-End User & Security Workflow](#9-end-to-end-user--security-workflow)
10. [API Endpoints & Swagger](#10-api-endpoints--swagger)
11. [Current POC Status & Known Limitations](#11-current-poc-status--known-limitations)
12. [Troubleshooting & Common Issues](#12-troubleshooting--common-issues)

---

## 1. Key Architecture & Security Highlights

* **Zero Complete Private Key Reconstruction**:
  The complete master private key $x$ is **NEVER** materialized, formed, or reconstructed in any variable, buffer, process memory, or database table during key generation, address derivation, or transaction signing.
* **3-Domain Separation of Powers**:
  1. **Foundation Domain** (Institutional Administration): $t_F$-of-$n_F$ quorum (configured exclusively via `backend/.env`, default `9` nodes, threshold `5`).
  2. **Public Domain** (Decentralized Staking Quorum): $t_P$-of-$n_P$ quorum (default `9` nodes, threshold `5`).
  3. **Private Domain** (Sovereign User & Guardians): $t_U$-of-$n_U$ quorum (default `9` nodes, threshold `5`).
  All three domains are required simultaneously (`3-of-3 AND`) to authorize signing.
* **Single Source of Truth Topology (`topologyConfig.ts`)**:
  Node counts and thresholds are configured solely via the six `SARAL_*` variables in `backend/.env` (minimum 3 nodes per domain, strict majority $t > n/2$, max 255). Total cluster size is computed dynamically ($N = N_F + N_P + N_V$). Client overrides are rejected.
* **Distributed Key Generation (DKG)**:
  Uses Feldman Verifiable Secret Sharing (VSS). Nodes independently generate secret polynomials, exchange verifiable sub-shares, and aggregate public commitments. The aggregated public key is derived via elliptic curve point addition:
  $$Q = Q_{\text{Foundation}} + Q_{\text{Public}} + Q_{\text{Private}}$$
  The EVM Ethereum address is computed from $Q$ (`ethers.computeAddress(Q)`).
* **Zero-Address & Zero-Key Database Storage (`sessionWalletRegistry.ts`)**:
  PostgreSQL stores **zero** private keys, **zero** plaintext secret shares, **zero** wallet addresses, and **zero** aggregated public keys (the legacy `wallets` table was removed in migration `005`). On login or server restart, the backend queries pinned nodes for public share points ($P_i = s_i \cdot G$), computes Lagrange interpolation in the exponent, and caches the derived address strictly in an ephemeral in-memory session map (`ACCESS_TOKEN_TTL_SECONDS`, default 15 minutes).
* **Multi-Tenant Encrypted Node Storage**:
  Key shares are encrypted with **AES-256-GCM** using domain-separated keys and stored across isolated node storage (`fileStore`, sandbox vault, or Docker containers) pinned via Rendezvous (HRW) hashing in `wallet_placements`.
* **Zero-Trust Access Policies (`locationService.ts`)**:
  Access evaluation and transaction signing enforce MFA verification, original `loginMethod` matching, timezone-aware working hours, Haversine GPS geofencing (`radiusKm`, default `25 km`), and a 24-hour impossible-velocity check (`> 1,200 km/h` over `> 5 km`).
* **Guarded Break-Glass Recovery (`recoveryService.ts`)**:
  Generates an independent 3-of-5 Shamir recovery secret at wallet creation with a mandatory timelock challenge window (default `48h`), sovereign user cancellation, and Feldman commitment verification. *(See [Section 11](#11-current-poc-status--known-limitations) for current POC boundaries.)*
* **Adaptive Multi-Asset Economic Security (`economicService.ts`)**:
  Tracks Total Value Secured (TVS), staking reserves, fee routing, and slashing telemetry.

---

## 2. Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, TypeScript, Vite 6, React Router DOM 6, Axios |
| **Backend** | Node.js, TypeScript, Express 5, Prisma ORM 6, `tsx`, Helmet, `express-rate-limit`, Zod 4 |
| **Cryptography** | `@noble/curves/secp256k1`, `ethers` v6, Feldman VSS, Paillier MtA, AES-256-GCM, HKDF/scrypt |
| **Database** | PostgreSQL 16 (Local or Docker container via `docker-compose.yml`) |
| **Authentication** | Google OAuth 2.0 (`google-auth-library`), Mobile Number + OTP, 2FA MFA, JWT |
| **Blockchain** | MST Testnet (Chain ID: `91562037`, RPC: `https://testnetrpc.mstblockchain.com`) |

---

## 3. Folder Structure

```text
saral-poc/
├── backend/
│   ├── config/
│   │   └── topology.json         # Cluster topology definition
│   ├── prisma/
│   │   └── schema.prisma         # Prisma ORM schema & relations
│   ├── src/
│   │   ├── config/               # env.ts, topologyConfig.ts, db.ts, swagger.ts
│   │   ├── controllers/          # auth, mfa, profile, wallet, device, topology, activity
│   │   ├── crypto/               # DKG, threshold ECDSA, mpcCoordinator, shamirField, paillierCrypto
│   │   ├── db/                   # schema.sql & SQL migrations (incl. 005_remove_wallet_address_and_public_key.sql)
│   │   ├── middleware/           # authGuard, cookieParser, csrf, errorHandler
│   │   ├── nodes/                # nodeLauncher, dockerComposeGen
│   │   ├── participant/          # MPC participant daemons, IPC protocol, nodeIdentityManager
│   │   ├── routes/               # auth, mfa, profile, wallet, devices, topology, activity
│   │   ├── scripts/              # clearDb.ts
│   │   ├── services/             # authService, walletService, sessionWalletRegistry, locationService, recoveryService, nodeClusterService, economicService, etc.
│   │   ├── storage/              # Hardened per-node encrypted FileStore
│   │   ├── topology/             # HRW rendezvous placement, allocation, apply
│   │   ├── utils/                # jwt, crypto, errors, logger (with address/key redaction), validation
│   │   ├── app.ts                # Express app setup & middleware
│   │   ├── bootstrap.ts          # Startup initialization
│   │   └── server.ts             # Server entry point
│   ├── .env.example
│   ├── package.json
│   └── tsconfig.json
├── frontend/
│   ├── src/
│   │   ├── api/                  # client.ts (Axios), endpoints.ts
│   │   ├── components/           # Navbar.tsx
│   │   ├── hooks/                # useAuth.tsx, useLocation.ts
│   │   ├── pages/
│   │   │   ├── Settings/         # AccountSection, WorkingHoursSection, DevicesSection, RecoverySection, AdvancedSection
│   │   │   ├── Wallet/           # WalletHeader, SendForm, TransactionList
│   │   │   ├── ActivityLog.tsx
│   │   │   ├── Login.tsx
│   │   │   ├── Mfa.tsx
│   │   │   ├── Review.tsx
│   │   │   ├── Settings.tsx
│   │   │   ├── Wallet.tsx
│   │   │   └── WorkingPolicy.tsx
│   │   ├── types/                # api.ts
│   │   ├── App.tsx
│   │   ├── index.css
│   │   └── main.tsx
│   ├── .env.example
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
├── docker-compose.yml            # PostgreSQL 16 service (host port 5433)
├── package.json                  # Root runner scripts (concurrently)
└── README.md
```

---

## 4. Prerequisites

* **Node.js**: v18.0.0 or higher (v20+ recommended). Check with `node -v`.
* **npm**: v9.0.0 or higher. Check with `npm -v`.
* **PostgreSQL**: v14, v15, or v16 running locally or via Docker (`docker compose up -d postgres`).
* **Git** installed.

---

## 5. Quick Start & Setup Instructions

### Step 1: Install Dependencies

From the repository root:
```bash
npm install
npm --prefix backend install
npm --prefix frontend install
```

### Step 2: Configure Environment Variables

1. **Backend Environment**:
   ```bash
   cp backend/.env.example backend/.env
   ```
   Key values in `backend/.env`:
   ```env
   PORT=3001
   NODE_ENV=development
   DATABASE_URL=postgresql://saral:saral_secret@localhost:5433/saral
   JWT_SECRET=change_me_min_32_chars_jwt_secret
   REFRESH_TOKEN_SECRET=change_me_min_32_chars_refresh
   CSRF_SECRET=change_me_csrf_secret
   FRONTEND_URL=http://localhost:5173
   RPC_URL=https://testnetrpc.mstblockchain.com
   CHAIN_ID=91562037

   # Node topology (single source of truth)
   SARAL_FOUNDATION_NODES=9
   SARAL_PUBLIC_NODES=9
   SARAL_PRIVATE_NODES=9
   SARAL_FOUNDATION_THRESHOLD=5
   SARAL_PUBLIC_THRESHOLD=5
   SARAL_PRIVATE_THRESHOLD=5
   ```
   *(If using a local PostgreSQL instance instead of Docker, adjust `DATABASE_URL` port/credentials accordingly, e.g. port `5432`.)*

2. **Frontend Environment**:
   ```bash
   cp frontend/.env.example frontend/.env
   ```
   Verify `frontend/.env`:
   ```env
   VITE_GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
   ```

### Step 3: Setup & Initialize the Database

* **Option A: Using Docker (Recommended)**:
  ```bash
  docker compose up -d postgres
  ```
* **Option B: Using Local PostgreSQL**:
  Ensure PostgreSQL is running on port `5432` (or update `DATABASE_URL`).

* **Generate Prisma Client & Push Schema**:
  ```bash
  cd backend
  npm run db:generate
  npm run db:push
  cd ..
  ```

### Step 4: Start the Development Servers

Run both Backend and Frontend concurrently from the project root:
```bash
npm run dev
```

* **Frontend UI**: [http://localhost:5173](http://localhost:5173)
* **Backend API**: [http://localhost:3001](http://localhost:3001)
* **Swagger API Docs**: [http://localhost:3001/docs](http://localhost:3001/docs)

---

## 6. All Necessary CLI Commands

### Root Workspace Commands

| Command | Description |
|---|---|
| `npm run setup` | Generates Prisma client and builds backend + frontend |
| `npm run dev` | Runs backend (`localhost:3001`) and frontend (`localhost:5173`) concurrently |
| `npm run backend` | Starts backend development server (`tsx watch src/server.ts`) |
| `npm run frontend` | Starts frontend Vite dev server |
| `npm run build` | Builds both backend (`tsc`) and frontend (`vite build`) |
| `npm run start` | Starts backend production server (`node dist/server.js`) |
| `npm test` | Runs backend test suite (`tests/*.test.ts`) if present |
| `npm run typecheck` | Runs `tsc --noEmit` on backend and Vite build on frontend |
| `npm run nodes:start` | Launches local MPC participant storage nodes |
| `npm run topology:apply` | Validates and applies topology cluster allocation |
| `npm run db:clear` | Clears test data from the database safely |

### Backend Specific Commands (`cd backend`)

| Command | Description |
|---|---|
| `npm run dev` | Run backend in watch mode with `tsx` |
| `npm run build` | Compile TypeScript to `dist/` |
| `npm run start:prod` | Run compiled server (`node dist/server.js`) |
| `npm run typecheck` | Type-check backend without emitting JS |
| `npm run db:generate` | Generate `@prisma/client` from `prisma/schema.prisma` |
| `npm run db:push` | Push Prisma schema to PostgreSQL |
| `npm run db:studio` | Open Prisma Studio web GUI |
| `npm run db:migrate` | Apply `src/db/schema.sql` via `psql` (`localhost:5433`) |
| `npm run db:clear` | Wipe records in database tables |
| `npm run docker:compose:gen` | Generate `backend/docker-compose.generated.yml` for node containers |
| `npm run nodes:start` | Spawn background MPC participant node processes |
| `npm run topology:apply` | Validate and apply cluster topology configuration |
| `npm test` | Run backend tests (`tsx --test tests/*.test.ts`) |

### Frontend Specific Commands (`cd frontend`)

| Command | Description |
|---|---|
| `npm run dev` | Start Vite local dev server with HMR |
| `npm run build` | Build production assets to `frontend/dist` |
| `npm run preview` | Preview the production build locally |

---

## 7. Environment Variables Reference

| Variable | Default Value | Description |
|---|---|---|
| `PORT` | `3001` | Express backend listening port |
| `NODE_ENV` | `development` | Environment mode (`development`, `test`, `production`) |
| `DATABASE_URL` | `postgresql://postgres:secret@localhost:5432/saral` | PostgreSQL connection string |
| `FRONTEND_URL` | `http://localhost:5173` | Allowed CORS origin |
| `JWT_SECRET` | `32+ chars` | Secret for signing Access Tokens |
| `JWT_EXPIRES_IN` | `15m` | JWT string expiry |
| `REFRESH_TOKEN_SECRET` | `32+ chars` | Secret for signing Refresh Tokens |
| `CSRF_SECRET` | `16+ chars` | Secret for CSRF protection |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | In-memory session wallet & access token TTL (seconds) |
| `REFRESH_TOKEN_TTL_DAYS` | `7` | Refresh token lifetime (days) |
| `GOOGLE_CLIENT_ID` | OAuth Client ID | Google Cloud OAuth 2.0 Web Client ID |
| `GOOGLE_CLIENT_SECRET` | `""` | Google Cloud OAuth Client Secret |
| `GOOGLE_REDIRECT_URI` | `http://localhost:5173/login` | Authorized redirect URI |
| `SMS_PROVIDER_KEY` | `dev-sms-key` | SMS provider key |
| `RPC_URL` | `https://testnetrpc.mstblockchain.com` | EVM Blockchain RPC endpoint |
| `CHAIN_ID` | `91562037` | Target blockchain chain ID |
| `TIME_TOLERANCE_MINUTES` | `0` | Grace window (minutes) around working hours |
| `LOCATION_RADIUS_KM` | `25` | Default geofence radius in kilometers |
| `SARAL_FOUNDATION_NODES` | `9` | Foundation domain node count (min `3`) |
| `SARAL_FOUNDATION_THRESHOLD` | `5` | Foundation quorum threshold (`> count / 2`) |
| `SARAL_PUBLIC_NODES` | `9` | Public domain node count (min `3`) |
| `SARAL_PUBLIC_THRESHOLD` | `5` | Public quorum threshold (`> count / 2`) |
| `SARAL_PRIVATE_NODES` | `9` | Private domain node count (min `3`) |
| `SARAL_PRIVATE_THRESHOLD` | `5` | Private quorum threshold (`> count / 2`) |
| `SARAL_REUSE_EXISTING_CONTAINERS` | `true` | Reuse existing node containers across sessions |
| `SARAL_CREATE_CONTAINERS_ON_LOGIN` | `false` | Whether to provision containers during login |
| `SARAL_PERSISTENT_NODE_STORAGE` | `true` | Persist encrypted shares to node storage |

---

## 8. Database Schema & Prisma

PostgreSQL is managed via Prisma ORM (`backend/prisma/schema.prisma`):

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
    users ||--o{ recovery_records : manages
```

* `users`: User identity (`google_id`, `email`, `mobile`, `login_method`).
* `mfa`: 2FA state (`type`, `secret`, `verified_at`).
* `work_policy`: Permitted working hours (`start_time`, `end_time`, `timezone`) and GPS geofence (`city`, `lat`, `lng`, `radius_km`).
* `wallet_placements`: Pinned Rendezvous (HRW) node IDs, per-domain thresholds, `epoch`, `manifest_hash`, and `protocol_version`.
* `key_shares`: **Zero-Key storage** — stores only `category`, `share_index`, `n`, `threshold`, `container_id`, and `container_name`.
* `transactions`: `tx_hash`, recipient `to_address`, `amount`, `status`, and timestamp (no sender address or public key stored).
* `access_logs`: Audit log of policy evaluations (`allowed`, `reason`, `lat`, `lng`, `attempted_at`).
* `security_event_logs`: Hash-chained security audit trail (`event_type`, `severity`, `details`, `previous_hash`, `entry_hash`).
* `otps`: HMAC-SHA256 hashed login/MFA OTP codes with expiration and usage tracking.
* `recovery_records`: Schema table for break-glass recovery lifecycle records.

---

## 9. End-to-End User & Security Workflow

### Step 1: Authentication (`/login`)
* **Google OAuth** or **Mobile OTP**: Looks up (or creates) the user in `users`, issues an initial JWT (`mfaVerified: false`), and returns `hasPolicy` and `hasWallet`.
* In `development` mode, mobile login OTPs are printed to the backend console (`[SMS OTP AUTH] ... | Code: xxxxxx`).

### Step 2: MFA Verification (`/mfa`)
* Dispatches and verifies a 6-digit MFA OTP (`mfaService.ts`), updates `mfa.verifiedAt`, and issues an upgraded JWT (`mfaVerified: true`).
* **First-time users (`hasPolicy === false`)** proceed to `/working-policy` → `/review` → `/wallet`.
* **Returning users (`hasPolicy === true`)** immediately evaluate `POST /api/wallet/check-access` using browser GPS coordinates and redirect straight to `/wallet` if within policy.

### Step 3: Working Policy & Confirm (`/working-policy`, `/review`)
* Configure working hours (e.g., `09:00`–`18:00`), timezone, city, and GPS coordinates (default geofence radius `25 km`).
* On `/review`, clicking **Confirm** validates current server time and location via `/api/wallet/check-access`.

### Step 4: Wallet Creation or Re-derivation (`/wallet`)
* **First-time user (`hasWallet === false`)**: Click **Create wallet** (`POST /api/wallet/generate`) to execute 3-Domain MPC DKG, pin HRW node placement, deploy AES-256-GCM encrypted shares to nodes, and initialize Break-Glass Recovery. Each user can create at most one wallet.
* **Returning user (`hasWallet === true`)**: `sessionWalletRegistry.ts` queries the pinned nodes for public share points ($s_i \cdot G$), derives $Q = Q_F + Q_P + Q_U$ and the EVM address in memory, and fetches the live MST Testnet balance without storing keys or addresses in PostgreSQL.

### Step 5: Threshold MPC Signing (`POST /api/wallet/sign`)
* Evaluates `evaluateAccessPolicy()` (MFA, `loginMethod` match, server-side working hours in `policy.timezone`, 24-hour velocity check, and Haversine geofence radius).
* Coordinates interactive 3-domain threshold ECDSA signing (`mpcCoordinator.ts`) and broadcasts the signed raw transaction to the MST Testnet (`chainService.ts`).

### Step 6: Settings, Devices, Recovery & Activity (`/settings`, `/activity`)
* `/settings` consolidates Account info, Working Hours updates, Devices & Guardians enrollment/revocation, Break-Glass Recovery (initiate / countdown / cancel), and Advanced Topology & Economic stats.
* `/activity` displays unified `access_logs` and `security_event_logs`. *(Legacy routes `/devices`, `/topology`, `/recovery`, `/security` redirect to `/settings`.)*

---

## 10. API Endpoints & Swagger

Interactive Swagger UI documentation is available at **[http://localhost:3001/docs](http://localhost:3001/docs)**.

### Summary of Routes

* **Health**:
  * `GET /api/health` — API health and startup metrics
* **Auth** (`/api/auth`):
  * `POST /api/auth/google` — Google OAuth credential verification
  * `POST /api/auth/otp/request` — Request mobile login OTP
  * `POST /api/auth/otp/verify` — Verify login OTP and issue JWT tokens
* **MFA** (`/api/mfa`):
  * `POST /api/mfa/send` — Dispatch MFA OTP
  * `POST /api/mfa/verify` — Verify MFA OTP and issue `mfaVerified: true` token
* **Profile & Policy** (`/api/profile`):
  * `GET /api/profile` — Fetch profile status (`mfaVerified`, `hasPolicy`, `hasWallet`) and policy
  * `POST /api/profile/policy` — Save or update time & geofencing policy
* **Wallet, Signing & Recovery** (`/api/wallet`):
  * `GET /api/wallet` — Derive/retrieve wallet metadata and live balance
  * `POST /api/wallet/generate` — Execute 3-Domain MPC DKG (once per user)
  * `POST /api/wallet/check-access` — Evaluate Zero-Trust policy gate
  * `POST /api/wallet/sign` — Execute Threshold MPC ECDSA signing & broadcast
  * `GET /api/wallet/transactions` — Fetch transaction history
  * `GET /api/wallet/cluster-health` — Real-time health status of configured storage nodes
  * `GET /api/wallet/economic-stats` — Economic security state, parameters, and slashing history
  * `POST /api/wallet/recovery/initiate` — Initiate break-glass recovery with timelock
  * `POST /api/wallet/recovery/cancel` — Challenge & cancel active recovery request
  * `POST /api/wallet/recovery/approve` — Submit custodian approval & share
  * `POST /api/wallet/recovery/execute` — Execute guarded recovery verification
  * `GET /api/wallet/recovery/logs` — Fetch recovery audit logs
* **Devices & Guardians** (`/api/devices`):
  * `GET /api/devices` — List enrolled private-domain devices & guardians
  * `POST /api/devices/enroll` — Enroll a device
  * `POST /api/devices/guardian` — Enroll a guardian
  * `DELETE /api/devices/:id` — Revoke a device/guardian
* **Topology** (`/api/topology`):
  * `GET /api/topology` — Active dynamic cluster topology
  * `GET /api/topology/nodes` — Node list across domains
  * `GET /api/topology/placement` — User's pinned HRW placement
* **Activity** (`/api/activity`):
  * `GET /api/activity` — Fetch access and security audit logs

---

## 11. Current POC Status & Known Limitations

1. **Break-Glass Recovery (`recoveryService.ts` / `RecoverySection.tsx`)**:
   * Timelock enforcement, cancellation, custodian share verification, and JSON audit persistence (`backend/.saral_registry/recovery_state.json`) are implemented.
   * However, `executeGuardedRecovery()` computes a PSS zero-polynomial locally without applying share rotation to `nodeCluster` / `nodeFileStore` / `mpcParticipantDaemon`, and `RecoverySection.tsx` only exposes Start, Countdown, and Cancel (no UI for custodian approval/execution). The Prisma `recovery_records` table is currently unused by `recoveryService.ts`.
2. **Send Form GPS Coordinates (`SendForm.tsx`)**:
   * `evaluateAccessPolicy()` requires `lat` and `lng`, while `SendForm.tsx` currently submits `{ toAddress, amount }` without coordinates. Sending via API clients works when `lat`/`lng` are supplied in the payload.
3. **MFA Freshness**:
   * `authGuard.ts` (`requireMfa`) verifies `mfaVerified: true` in the JWT; a strict 5-minute `mfa.verifiedAt` recency check is not yet enforced at the middleware layer.

---

## 12. Troubleshooting & Common Issues

### 1. Wallet balance shows `0.0000 MSTC` on Refresh even when funded
* **Cause**: In `backend/src/services/chainService.ts`, `getBalance()` enforces a 4,000 ms RPC timeout and catches any RPC/network error (such as intermittent `500 Internal Server Error` or TLS drops from `https://testnetrpc.mstblockchain.com`), returning `'0.0000'` as a fallback (`ethers.formatEther(0n)` returns `'0.0'`, whereas `'0.0000'` indicates the RPC call failed or timed out).
* **Fix**: Retry refresh when the testnet RPC stabilizes, or point `RPC_URL` in `backend/.env` to a reliable EVM RPC node.

### 2. `Can't reach database server at localhost:5432` or `5433`
* **Fix**:
  1. If using Docker:
     ```bash
     docker compose up -d postgres
     ```
     Use port `5433` in `backend/.env`:
     ```env
     DATABASE_URL=postgresql://saral:saral_secret@localhost:5433/saral
     ```
  2. If using local PostgreSQL:
     ```bash
     sudo systemctl start postgresql
     ```
     Ensure `DATABASE_URL` matches your local PostgreSQL port (`5432`) and credentials.

### 3. Google Sign-In gives `Audience Mismatch` or Error 500
* **Fix**: Ensure `GOOGLE_CLIENT_ID` in `backend/.env` and `VITE_GOOGLE_CLIENT_ID` in `frontend/.env` match identically, then restart both servers.

### 4. Missing dev OTP on Login / MFA
* **Fix**: Check the backend terminal output. In `development` mode, OTPs are logged to stdout (`[SMS OTP AUTH] ...` and `[MFA OTP CHALLENGE] ...`).

### 5. Resetting Database State
```bash
cd backend
npm run db:push
npm run db:clear
```

---

## 📄 License & Intellectual Property

SARAL POC architecture is developed in alignment with Separation of Powers Non-Custodial Key Management and Multi-Party Computation patent specifications. All rights reserved.
