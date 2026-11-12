# SARAL — 3-Domain Multi-Party Computation (MPC) Wallet

A non-custodial cryptographic key management system and Web3 wallet implementing a **3-Domain Separation of Powers** architecture with **Genuine Threshold ECDSA (secp256k1)**, **Distributed Key Generation (DKG)**, **Zero-Key Database Storage**, and **Adaptive Zero-Trust Context Policies** (Working Hours & Geofencing).

Compatible with EVM chains and the **MST Testnet**.

---

## 📑 Table of Contents

1. [Key Architecture & Patent Highlights](#1-key-architecture--patent-highlights)
2. [Tech Stack](#2-tech-stack)
3. [Folder Structure](#3-folder-structure)
4. [Prerequisites](#4-prerequisites)
5. [Quick Start & Setup Instructions](#5-quick-start--setup-instructions)
6. [All Necessary CLI Commands](#6-all-necessary-cli-commands)
7. [Environment Variables Reference](#7-environment-variables-reference)
8. [Database Schema & Prisma](#8-database-schema--prisma)
9. [End-to-End User & Security Workflow](#9-end-to-end-user--security-workflow)
10. [API Endpoints & Swagger](#10-api-endpoints--swagger)
11. [Troubleshooting & Common Issues](#11-troubleshooting--common-issues)

---

## 1. Key Architecture & Patent Highlights

* **CRITICAL GUARANTEE: Zero Complete Private Key Reconstruction**:
  The complete master private key $x$ is **NEVER** materialized, formed, or reconstructed in any variable, buffer, process memory, or database table during key generation or transaction signing.
* **3-Domain Separation of Powers**:
  1. **Foundation Domain** (Institutional Administration): $t_F$-of-$n_F$ quorum (configured via `.env`, e.g. 9 nodes, threshold 5).
  2. **Public Domain** (Decentralized Staking Quorum): $t_P$-of-$n_P$ quorum (configured via `.env`, e.g. 9 nodes, threshold 5).
  3. **Private Domain** (Sovereign User & Guardians): $t_U$-of-$n_U$ quorum (configured via `.env`, e.g. 9 nodes, threshold 5).
* **Distributed Key Generation (DKG)**:
  Uses Feldman Verifiable Secret Sharing (VSS). Nodes independently generate secret polynomials, exchange verifiable sub-shares, and aggregate public commitments. The aggregated public key is derived via elliptic curve point addition:
  $$Q = Q_{\text{Foundation}} + Q_{\text{Public}} + Q_{\text{Private}}$$
  The EVM Ethereum address is computed directly from $Q$ (`ethers.computeAddress(Q)`).
* **Multi-Tenant Node Cluster**:
  Key shares are encrypted with **AES-256-GCM** using domain-separated HKDF keys and stored strictly across isolated node daemons/containers according to the dynamic topology configured in `.env` (e.g. 27 nodes for 9/9/9).
* **Zero-Key Database Storage**:
  PostgreSQL stores **zero** private keys and **zero** plaintext secret shares. Only non-sensitive public metadata (address, public key, container IDs, audit logs) is stored in the database.
* **Guarded Break-Glass Recovery (Patent FIG. 3)**:
  Timelock-based recovery lifecycle requiring custodian threshold approvals and anti-tamper security audit logs.
* **Adaptive Multi-Asset Economic Security (Patent FIG. 4)**:
  Dynamically tracks Total Value Secured (TVS) and validates staking thresholds against transaction values.
* **Zero-Trust Access Policies**:
  Transactions and key access are strictly gated by time-of-day working hours and physical GPS coordinates (Haversine geofence calculation).

---

## 2. Tech Stack

| Layer | Technologies |
|---|---|
| **Frontend** | React 18, TypeScript, Vite, React Router DOM, Axios, CSS Modules / Modern CSS |
| **Backend** | Node.js, TypeScript, Express 5, Prisma ORM 6, TSX, Helmet, Rate-Limit, Cookie Parser |
| **Cryptography** | `@noble/curves/secp256k1`, Ethers v6, Feldman VSS, Paillier MtA, AES-256-GCM |
| **Database** | PostgreSQL 16 (Local or Docker container) |
| **Authentication** | Google OAuth 2.0 (Google Identity Services), Mobile Number + OTP, 2FA MFA, JWT |
| **Blockchain** | MST Testnet (Chain ID: `91562037`, RPC: `https://testnetrpc.mstblockchain.com`) |

---

## 3. Folder Structure

```
saral-poc/
├── backend/
│   ├── prisma/
│   │   └── schema.prisma         # Prisma ORM schema & relations
│   ├── src/
│   │   ├── config/               # env.ts, db.ts (Prisma client), swagger.ts
│   │   ├── controllers/          # auth, mfa, profile, wallet, device, topology controllers
│   │   ├── crypto/               # DKG, threshold ECDSA, secp256k1 math, Shamir field, Paillier MtA
│   │   ├── db/                   # schema.sql, migrations
│   │   ├── middleware/           # authGuard, errorHandler, cookieParser, csrf
│   │   ├── nodes/                # nodeLauncher, dockerComposeGen
│   │   ├── participant/          # MPC participant daemons, IPC protocol, registry
│   │   ├── routes/               # Express route definitions
│   │   ├── services/             # authService, walletService, locationService, recoveryService, etc.
│   │   ├── topology/             # HRW rendezvous placement, allocation
│   │   ├── utils/                # jwt, crypto, errors, logger, validation (Zod)
│   │   ├── app.ts                # Express application setup & security middleware
│   │   └── server.ts             # Server entry point
│   ├── tests/                    # Integration, crypto, recovery, independence & topology tests
│   ├── .env.example
│   ├── package.json
│   └── tsconfig.json
├── frontend/
│   ├── src/
│   │   ├── api/                  # client.ts (Axios), endpoints.ts
│   │   ├── components/           # Navbar.tsx
│   │   ├── hooks/                # useAuth.tsx, useLocation.ts
│   │   ├── pages/                # Login, Mfa, WorkingPolicy, Review, Wallet, Settings, ActivityLog
│   │   ├── types/                # TypeScript API interfaces
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   ├── .env.example
│   ├── package.json
│   ├── vite.config.ts
│   └── tsconfig.json
├── docker-compose.yml            # PostgreSQL & container setup
├── package.json                  # Root runner scripts (concurrently)
└── README.md
```

---

## 4. Prerequisites

* **Node.js**: v18.0.0 or higher (v20+ recommended). Check with `node -v`.
* **npm**: v9.0.0 or higher. Check with `npm -v`.
* **PostgreSQL**: v14, v15, or v16 running natively or via Docker.
* **Git** installed.

---

## 5. Quick Start & Setup Instructions

### Step 1: Install Dependencies

From the repository root:
```bash
# Install root, backend, and frontend packages
npm install
npm --prefix backend install
npm --prefix frontend install
```

### Step 2: Configure Environment Variables

1. **Backend Environment**:
   ```bash
   cp backend/.env.example backend/.env
   ```
   Open `backend/.env` and verify key settings:
   ```env
   PORT=3001
   NODE_ENV=development
   DATABASE_URL=postgresql://saral:saral_secret@localhost:5432/saral?host=/tmp
   # If using Docker PostgreSQL:
   # DATABASE_URL=postgresql://saral:saral_secret@localhost:5433/saral
   JWT_SECRET=saral_dev_jwt_secret_key_2024_change_me_min32
   REFRESH_TOKEN_SECRET=saral_refresh_secret_change_in_production_min_32_ch
   CSRF_SECRET=saral_csrf_secret_change_min16
   GOOGLE_CLIENT_ID=
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   FRONTEND_URL=http://localhost:5173
   RPC_URL=https://testnetrpc.mstblockchain.com
   CHAIN_ID=91562037

   # Node topology. These six values are the only place counts and thresholds are set.
   SARAL_FOUNDATION_NODES=9
   SARAL_PUBLIC_NODES=9
   SARAL_PRIVATE_NODES=9
   SARAL_FOUNDATION_THRESHOLD=5
   SARAL_PUBLIC_THRESHOLD=5
   SARAL_PRIVATE_THRESHOLD=5
   # Rules: each count >= 3, threshold > count/2, threshold <= count.
   # Total nodes = sum of the three counts (not configurable).
   ```

2. **Frontend Environment**:
   ```bash
   cp frontend/.env.example frontend/.env
   ```
   Verify `frontend/.env`:
   ```env
   VITE_GOOGLE_CLIENT_ID=
   ```

### Step 3: Setup & Initialize the Database

* **Option A: Using Docker (Recommended for quick run)**:
  ```bash
  docker compose up -d postgres
  ```
* **Option B: Using Local PostgreSQL Daemon**:
  Ensure PostgreSQL is running on port 5432 or socket `/tmp`.

* **Generate Prisma Client & Push Tables**:
  ```bash
  cd backend
  npm run db:generate
  npm run db:push
  cd ..
  ```

### Step 4: Start the Development Servers

Run both Backend and Frontend concurrently with one command from the project root:
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
| `npm run dev` | Runs backend (`localhost:3001`) and frontend (`localhost:5173`) concurrently |
| `npm run backend` | Starts backend development server (`tsx watch src/server.ts`) |
| `npm run frontend` | Starts frontend Vite dev server |
| `npm run build` | Builds both backend (TypeScript `tsc`) and frontend (`vite build`) |
| `npm run start` | Starts backend production server (`node dist/server.js`) |
| `npm test` | Runs the entire backend test suite (`tests/*.test.ts`) |
| `npm run typecheck` | Type-checks both backend and frontend without emitting code |
| `npm run nodes:start` | Launches the local MPC participant storage nodes |
| `npm run topology:apply` | Computes and applies topology cluster allocation |
| `npm run db:clear` | Resets and wipes test data from the database safely |

### Backend Specific Commands (`cd backend`)

| Command | Description |
|---|---|
| `npm run dev` | Run backend in watch mode with `tsx` |
| `npm run build` | Compile TypeScript to JavaScript in `dist/` |
| `npm run db:generate` | Generates `@prisma/client` from `prisma/schema.prisma` |
| `npm run db:push` | Synchronizes Prisma schema directly with the database without migrations |
| `npm run db:studio` | Opens Prisma Studio (Web GUI for database inspection) |
| `npm run db:migrate` | Runs SQL migrations using `psql` |
| `npm run db:clear` | Clears all tables in the database |
| `npm run docker:compose:gen` | Generates dynamic `docker-compose.nodes.yml` for MPC node containers |
| `npm run nodes:start` | Spawns background MPC participant daemons |
| `npm run topology:apply` | Validates and pins participant placement topology |
| `npm test` | Executes backend tests with Node test runner |

### Frontend Specific Commands (`cd frontend`)

| Command | Description |
|---|---|
| `npm run dev` | Starts Vite local dev server with HMR |
| `npm run build` | Builds optimized production assets to `frontend/dist` |
| `npm run preview` | Previews the production build locally |

---

## 7. Environment Variables Reference

| Variable | Default Value | Description |
|---|---|---|
| `PORT` | `3001` | Express backend listening port |
| `NODE_ENV` | `development` | Environment mode (`development`, `test`, `production`) |
| `DATABASE_URL` | `postgresql://...` | PostgreSQL connection string |
| `FRONTEND_URL` | `http://localhost:5173` | Allowed CORS origin |
| `JWT_SECRET` | 32+ chars string | Secret for signing 15-minute Access Tokens |
| `REFRESH_TOKEN_SECRET` | 32+ chars string | Secret for signing 7-day Refresh Tokens |
| `CSRF_SECRET` | 16+ chars string | Secret for CSRF protection cookies |
| `GOOGLE_CLIENT_ID` | OAuth Client ID | Google Cloud OAuth 2.0 Web Client ID |
| `GOOGLE_CLIENT_SECRET` | OAuth Secret | Google Cloud OAuth Client Secret |
| `GOOGLE_REDIRECT_URI` | `http://localhost:5173/login` | Authorized redirect URI |
| `RPC_URL` | `https://testnetrpc.mstblockchain.com` | EVM Blockchain RPC endpoint |
| `CHAIN_ID` | `91562037` | Target blockchain chain identifier |
| `SARAL_FOUNDATION_NODES` | `9` | Institutional domain participant count (min 3) |
| `SARAL_FOUNDATION_THRESHOLD` | `5` | Institutional domain quorum threshold (strict majority > count/2) |
| `SARAL_PUBLIC_NODES` | `9` | Public validator participant count (min 3) |
| `SARAL_PUBLIC_THRESHOLD` | `5` | Public validator quorum threshold (strict majority > count/2) |
| `SARAL_PRIVATE_NODES` | `9` | Sovereign user/guardian participant count (min 3) |
| `SARAL_PRIVATE_THRESHOLD` | `5` | Sovereign domain quorum threshold (strict majority > count/2) |

---

## 8. Database Schema & Prisma

The database uses PostgreSQL managed via Prisma ORM (`backend/prisma/schema.prisma`):

```mermaid
erDiagram
    users ||--o| mfa : has
    users ||--o| work_policy : defines
    users ||--o| wallets : owns
    users ||--o{ key_shares : references
    users ||--o{ access_logs : logs
    users ||--o{ transactions : executes
    users ||--o{ otps : verifies
    users ||--o{ recovery_records : manages
    wallets ||--o{ wallet_placements : pinned
```

* `users`: Stores user identity (`google_id`, `mobile`, `login_method`).
* `mfa`: 2FA state, type (`otp`), and verification timestamp.
* `work_policy`: Permitted working hours (`start_time`, `end_time`) and GPS geofence (`city`, `lat`, `lng`, `radius_km`).
* `wallets`: EVM address, aggregated public key $Q$, threshold, total participants $n$, protocol version.
* `key_shares`: **Zero-Key storage**. Contains **only** `container_id`, `container_name`, domain category, and share index.
* `transactions`: Hash, recipient address, amount, and timestamp.
* `recovery_records`: Guarded Break-Glass recovery lifecycle and custodian signature states.
* `access_logs`: Audit log of policy evaluation attempts with timestamp, coordinates, and pass/fail reason.

---

## 9. End-to-End User & Security Workflow

### Step 1: Authentication (`/login`)
* **Google OAuth**: One-Tap sign-in verifies Google ID token via `google-auth-library`.
* **Mobile OTP**: Enter phone number (e.g. `+919876543210`). In `development` mode, the 6-digit OTP is printed to the server terminal (`[SMS OTP AUTH] ... CODE: xxxxxx`).

### Step 2: MFA Verification (`/mfa`)
* Dispatches a second-factor OTP code (printed in the backend console in dev mode).
* Enter the 6-digit code to verify the session and upgrade permissions.

### Step 3: Working Policy (`/working-policy`)
* Set allowable working hours (e.g., `09:00` to `22:00`).
* Set permitted city & GPS geofence with radius (e.g., Indore, `22.7196, 75.8577`, 25 km).

### Step 4: Wallet Initialization (`/wallet`)
* Click **Create Wallet** to trigger 3-Domain MPC DKG.
* The configured cluster nodes collaboratively sample polynomials and compute public commitments.
* Aggregated public key and EVM address are derived and displayed.
* Key shares are encrypted with AES-256-GCM and deployed to isolated node storage.

### Step 5: Send Transaction via Threshold MPC Signing
* Enter destination EVM address and amount.
* The system evaluates Zero-Trust policies (current time must be within working hours, coordinates must be within the geofence radius).
* Threshold quorums from **all 3 domains** contribute partial signatures using distributed nonces.
* A canonical Ethereum transaction is broadcast directly to the MST Testnet without reconstructing the private key.

### Step 6: Policy Enforcement & Rejection Test
* Change working hours to outside the current time or travel outside the geofence radius.
* Signing and access are immediately blocked with HTTP 403 Forbidden, and an audit trail is logged to `access_logs`.

---

## 10. API Endpoints & Swagger

Interactive Swagger UI documentation is available at:
👉 **[http://localhost:3001/docs](http://localhost:3001/docs)**

### Summary of Core Routes:

* **Auth**:
  * `POST /api/auth/google` — Google OAuth credential verification
  * `POST /api/auth/otp/request` — Request mobile login OTP
  * `POST /api/auth/otp/verify` — Verify login OTP and issue JWT tokens
* **MFA**:
  * `POST /api/mfa/send` — Dispatch MFA OTP
  * `POST /api/mfa/verify` — Verify MFA OTP
* **Profile & Policy**:
  * `GET /api/profile` — Fetch profile status, policy, and wallet info
  * `POST /api/profile/policy` — Save time & geofencing policy
* **Wallet**:
  * `GET /api/wallet` — Get current wallet metadata and on-chain balance
  * `POST /api/wallet/generate` — Execute 3-Domain MPC DKG
  * `POST /api/wallet/check-access` — Evaluate Zero-Trust policy gate
  * `POST /api/wallet/sign` — Execute Threshold MPC ECDSA signing & broadcast
  * `GET /api/wallet/transactions` — Fetch transaction history
  * `GET /api/wallet/cluster-health` — Real-time health status of 19 storage nodes
* **Recovery (Patent FIG. 3)**:
  * `POST /api/wallet/recovery/initiate` — Initiate break-glass recovery with timelock
  * `POST /api/wallet/recovery/approve` — Custodian approval submission
  * `POST /api/wallet/recovery/execute` — Execute guarded recovery ceremony
  * `GET /api/wallet/recovery/logs` — Audit log of recovery events

---

## 11. Troubleshooting & Common Issues

### 1. `Can't reach database server at /tmp:5432` or `localhost:5432`
* **Cause**: PostgreSQL server is stopped or connection string socket parameter is invalid.
* **Fix**:
  1. If running Docker:
     ```bash
     docker compose up -d postgres
     ```
     Ensure `DATABASE_URL` in `backend/.env` uses port `5433`:
     ```env
     DATABASE_URL=postgresql://saral:saral_secret@localhost:5433/saral
     ```
  2. If running local PostgreSQL on Linux:
     ```bash
     sudo systemctl start postgresql
     ```
     Ensure `DATABASE_URL` is:
     ```env
     DATABASE_URL=postgresql://saral:saral_secret@localhost:5432/saral
     ```

### 2. Google Sign-In gives `Audience Mismatch` or Error 500
* **Cause**: `GOOGLE_CLIENT_ID` in `backend/.env` and `VITE_GOOGLE_CLIENT_ID` in `frontend/.env` must match exactly.
* **Fix**:
  Ensure both `.env` files share the exact same Client ID, then restart the backend:
  ```bash
  cd backend && npm run dev
  ```

### 3. Missing dev OTP on Login
* **Fix**: Look at the terminal running `npm run dev` or the backend process. Development OTPs are printed directly to the console:
  ```
  [SMS OTP AUTH] Mobile: +919876543210 | Code: 123456
  ```

### 4. Re-running Database Migrations from Scratch
* If you need a clean database reset:
  ```bash
  cd backend
  npm run db:push
  # Or clear test records:
  npm run db:clear
  ```

---

## 📄 License & Intellectual Property

SARAL POC architecture is developed in alignment with Separation of Powers Non-Custodial Key Management and Multi-Party Computation patent specifications. All rights reserved.
