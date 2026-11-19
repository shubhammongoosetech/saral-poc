# SARAL Protocol — Distributed Key Generation & Web3 Wallet Architecture

A production-grade, architecture-first implementation of the **SARAL Protocol** (Separation-of-Powers Cryptographic Key Infrastructure).

SARAL distributes network trust, identity, and control-plane orchestration across three independent administrative realms: **Foundation Domain**, **Public Domain**, and **Private Domain**, ensuring private signing keys are never materialized in whole on any single server, database, or client device.

For complete cryptographic specifications, sequence diagrams, and mathematical formulations, see [SARAL_ARCHITECTURE.md](file:///d:/desktop/poc/saral-poc/SARAL_ARCHITECTURE.md).

---

## 1. Key Invariants & Features

1. **Mandatory TOTP MFA (RFC 6238):**
   - Pure Node.js crypto implementation of RFC 6238 Time-Based One-Time Password.
   - Initial enrollment generates QR code, secret key, and 8 single-use backup recovery codes (`XXXX-XXXX`).
   - Secrets are encrypted at rest using AES-256-GCM.
   - Returning users are challenged with TOTP without repeating enrollment.
2. **Authoritative Working Policy Engine:**
   - Enforced immediately post-MFA and evaluated on sensitive operations.
   - Time window checks with overnight span support using authoritative server time in IANA timezones.
   - Weekday validation (MON-SUN).
   - Haversine distance geofencing with fail-closed security.
3. **Zero-Address Persistence Mandate:**
   - Central PostgreSQL persists ZERO wallet addresses and ZERO signing private keys.
   - Persists only opaque key references (`key-mst-...`, `key-sol-...`, `key-btc-...`).
   - Addresses are derived deterministically in RAM upon authenticated requests.
4. **Single Logical Wallet Invariant:**
   - Exactly one wallet per user (`UNIQUE(user_id)`).
   - Repeat logins idempotently recompute the exact same addresses without initiating new DKGs:
     `MST_Login1 == MST_Login2`, `SOL_Login1 == SOL_Login2`, `BTC_Login1 == BTC_Login2`.
5. **Chain-Compatible Address Derivations:**
   - **MST Testnet (EVM):** EIP-55 checksummed `0x...` hex address.
   - **Solana Devnet:** Base58 Ed25519 public key.
   - **Bitcoin Testnet:** BIP-340/341 Taproot $X$-only point with BIP-350 Bech32m using `tb1p...` prefix.
6. **Docker-Only Persistence (24-Container Mesh):**
   - Exactly 24 containers defined in `infra/compose/full24.yml`:
     1 `postgres` + 1 `auth-server` + 3 `verifiers` + 15 `nodes` + 3 `coordinators` + 1 `web`.
   - Central persistence in named volume `saral_postgres_data`.
   - Node shares in isolated named volumes `node_f1_vault` through `node_r5_vault`.

---

## 2. Prerequisites

- **Go:** `1.24+` (or `1.27+`)
- **Node.js:** `20.x` or `22.x+`
- **Docker & Docker Compose:** Docker Compose v2+
- **Git**

---

## 3. Quick Start Commands

```bash
# 1. Clean build outputs
npm run clean

# 2. Build microservices, TypeScript SDK, and Frontend
npm run build

# 3. Start the full 24-container mesh in Docker
docker compose -f infra/compose/full24.yml up -d --build

# 4. Check container health status (24 containers)
docker compose -f infra/compose/full24.yml ps

# 5. Run automated end-to-end system verification (11 phases)
node scratch/test_full_v3_e2e.js

# 6. Run all unit and architecture tests
npm test

# 7. Stop Docker containers
docker compose -f infra/compose/full24.yml down
```

---

## 4. Project Structure

```text
saral-poc/
├── apps/
│   ├── web/               # React 19 + Vite + Tailwind CSS Web3 Wallet Frontend
│   └── auth-server/       # Node.js Auth Server (RS256 JWT, RFC 6238 MFA, Working Policy)
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
│   └── architecture/      # End-to-end architecture & cryptography verification suite
├── scratch/               # Automated test runners & verification scripts
├── README.md              # Project overview and runbook
└── SARAL_ARCHITECTURE.md  # Detailed architecture, threat model, and specifications
```

---

## 5. Scope

This release strictly covers **user onboarding, multi-factor authentication, working policy evaluation, per-user DKG, and multi-chain wallet address & balance viewing**. TSS signing, token transfers, swaps, and staking are reserved for future phases.
