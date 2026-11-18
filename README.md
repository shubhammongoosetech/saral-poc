# SARAL Protocol V3 — Clean Architecture Runtime

A modular, architecture-first implementation of the **SARAL Protocol** (Separation-of-Powers Cryptographic Key Infrastructure).

SARAL distributes network trust, identity, and control-plane orchestration across three independent administrative realms: **Foundation Domain**, **Public Domain**, and **Private Domain**.

---

## 1. Prerequisites

- **Go:** `1.24+` (or `1.27+`)
- **Node.js:** `20.x` or `22.x+`
- **Docker & Docker Compose:** Docker Compose v2+
- **Git**

---

## 2. Quick Start Commands

```bash
# 1. Clean generated build outputs
npm run clean

# 2. Build all Go microservices, TypeScript SDK, and Frontend
npm run build

# 3. Execute the full Architecture Runtime Test (Spawns 15 nodes, 3 coordinators, verifier)
npm run test
# OR
npm run verify:architecture

# 4. Start the 15-Node POC in Docker (23 containers)
npm run docker:poc

# 5. Check container statuses
npm run docker:status

# 6. Stop Docker containers
npm run docker:down
```

---

## 3. Project Structure

```text
saral-poc/
├── apps/
│   ├── web/               # React 18 + Vite Network Architecture Dashboard
│   └── auth-server/       # Stateless Asymmetric RS256 Auth Server
├── packages/
│   └── saral-sdk/         # Typed JSON-RPC 2.0 Client SDK
├── services/
│   ├── coordinator/       # Go Coordinator (Foundation, Public, Private)
│   ├── verifier/          # Go Stateless Verifier (Token validation)
│   └── saral-node/        # Reusable Go Node daemon (P2P Mesh + Vault identity)
├── infra/
│   ├── compose/
│   │   ├── poc15.yml      # 15-Node POC Compose configuration (23 containers)
│   │   └── full24.yml     # 24-Node Production Compose configuration (32 containers)
│   └── config/            # Infrastructure configurations
├── tests/
│   └── architecture/      # End-to-end architecture verification suite
├── Makefile               # Make targets mirroring npm scripts
├── README.md              # Project overview
├── ARCHITECTURE.md        # Technical architecture & threat model
└── RUNBOOK.md             # Operations & troubleshooting manual
```

---

## 4. Architecture Dashboard

When the frontend is running (`http://localhost:3000` via Docker or `npm run dev`):
- Displays real-time health for Foundation, Public, and Private domains.
- Displays enrolled vs online nodes.
- Shows live P2P connected peers and node public keys.
- Features **⚡ Run Network Probe**: dispatches authenticated probe requests through coordinators to all nodes, displaying real RTT latency and Ed25519 cryptographic acknowledgements.

---

## 5. Scope & Future Work

This Phase 3 release establishes the **clean, runnable distributed architecture and networking runtime**. Advanced cryptographic features (DKG, VSS, CGGMP21 threshold ECDSA, and blockchain transaction broadcasting) are scheduled for subsequent phases. Any calls to cryptographic stubs return an explicit `NOT_IMPLEMENTED (-32000)` response.
