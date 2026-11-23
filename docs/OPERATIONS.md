# SARAL Operations, Deployment & Runbook

This guide outlines system administration, deployment procedures, container topologies, health verification, and failure recovery protocols for the SARAL 3-Domain multi-curve cluster.

---

## 1. Cluster Topology & Network Port Map

The full production SARAL stack consists of 21 Go microservice containers and 3 application services (24 containers total) operating across 3 independent sovereign domains.

### Service Ports & Roles

| Service Name | Container / Host Port | Protocol | Domain | Function |
| :--- | :---: | :---: | :---: | :--- |
| **PostgreSQL 16** | `5432` | TCP | Host/Infra | Central metadata storage (opaque IDs only) |
| **Auth Server** | `3001` | HTTP / REST | Auth | Authentication, MFA, Working Policy, Address Derivation |
| **Web Frontend** | `5173` (Dev) / `80` (Prod) | HTTP | UI | React 18 Web3 Dashboard |
| **Foundation Verifier** | `8001` | HTTP / JSON-RPC | Foundation | Ed25519 token verification & audit logs |
| **Public Verifier** | `8002` | HTTP / JSON-RPC | Public | Ed25519 token verification & audit logs |
| **Private Verifier** | `8003` | HTTP / JSON-RPC | Private | Ed25519 token verification & audit logs |
| **Foundation Coordinator** | `9001` | HTTP / JSON-RPC | Foundation | Domain DKG session orchestration |
| **Public Coordinator** | `9002` | HTTP / JSON-RPC | Public | Domain DKG session orchestration |
| **Private Coordinator** | `9003` | HTTP / JSON-RPC | Private | Domain DKG session orchestration |
| **Nodes (15 total)** | `9101–9105` (Foundation)<br>`9106–9110` (Public)<br>`9111–9115` (Private) | HTTP / mTLS | All 3 | AVSS polynomial sharing & HybridDKG execution |

---

## 2. Strict Service Startup Order

Due to identity and token validation dependencies, services must be initialized in the exact following chronological order:

```text
Step 1: Verifiers (8001, 8002, 8003)
   │  • Load Genesis Public Keys (/run/secrets/auth_ed25519_pub.pem)
   │  • Establish token verification and audit log endpoints
   ▼
Step 2: Coordinators (9001, 9002, 9003)
   │  • Connect to respective domain verifiers
   │  • Establish internal relay channels and peer discovery
   ▼
Step 3: Distributed Nodes (9101–9115)
   │  • Initialize AES-256-GCM encrypted share vaults (/vault)
   │  • Register with Coordinator registries and begin peer heartbeats
   ▼
Step 4: Central PostgreSQL (5432) & Auth Server (3001)
   │  • Run Prisma migrations (clean, zero-seed initial state)
   │  • Connect to 3 Coordinators concurrently
   ▼
Step 5: Web Frontend (5173)
      • Connect to Auth Server at http://localhost:3001
```

---

## 3. Deployment Commands & Runbook

### Clean System Reset
To completely wipe stale containers, persistent volumes, and database records:
```bash
bash scripts/clean-all.sh
```

### Automated Fresh Setup
To build all Go binaries, initialize certificates, push database schemas, and verify cluster health:
```bash
bash scripts/fresh-setup.sh
```

### Local Development (Host UI + Docker Backend)
```bash
# 1. Start backend Go containers and database
npm run docker:nodes

# 2. Synchronize database schema
npm run prisma:migrate

# 3. Launch Auth Server and React Web Frontend concurrently
npm run dev
```

### Verification & Testing
```bash
# Run all unit, architecture, and cryptographic proof tests
npm test

# Run end-to-end verification script
bash scripts/verify-all.sh
```

---

## 4. Health Checks & Diagnostics

### Auth Server Health
```bash
curl -s http://localhost:3001/health | jq .
```
Expected output:
```json
{
  "status": "ok",
  "uptime": 120.5,
  "database": "CONNECTED",
  "coordinators": {
    "foundation": "HEALTHY",
    "public": "HEALTHY",
    "private": "HEALTHY"
  }
}
```

### Coordinator Health Check (JSON-RPC)
```bash
curl -s -X POST http://localhost:9001/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"saral_getNetworkStatus","params":{},"id":1}' | jq .
```

### Node Process Status
```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep saral-prod
```

---

## 5. Failure Modes & Crash Recovery

### 1. Single Node Crash ($f \le 1$)
- **Symptom:** One node container exits or fails to respond.
- **Protocol Behavior:** Cluster remains **100% operational**.
- **Explanation:** In an $n=5, t=1$ committee, the remaining 4 nodes meet the Echo Quorum ($Q_{\text{echo}} = 4$) and Completion Quorum ($Q_{\text{complete}} = 3$). DKG successfully reaches consensus with $\text{QUAL}$ containing the 4 active dealers.
- **Recovery:** Restart the container (`docker start <container_name>`). The node reads its persisted vault state from `/vault` upon restart.

### 2. Leader Crash During DKG
- **Symptom:** Current round leader fails to broadcast `HYBRID_DKG_PROPOSAL`.
- **Protocol Behavior:** Nodes timeout after `SARAL_LEADER_TIMEOUT_MS` (default: 5000ms), broadcast `HYBRID_DKG_LEADER_CHANGE`, and advance to round $r+1$. The next leader deterministically assumes coordination and completes the DKG.

### 3. Multiple Node Failures ($f \ge 2$)
- **Symptom:** 2 or more nodes in a single domain crash simultaneously.
- **Protocol Behavior:** Protocol **fails closed**.
- **Explanation:** Only 3 nodes are alive, which is strictly less than $Q_{\text{echo}} = 4$. No nodes emit READY, preventing any partial or corrupt key agreement from taking place.
- **Recovery:** Bring down nodes back online before retrying wallet onboarding.

---

## 6. Secrets Hygiene & Security Alerts

> [!CAUTION]
> **CRITICAL SECURITY REQUIREMENT: Google OAuth Client Secret Rotation**
> Any real Google OAuth credentials previously present in local development files have been purged and sanitized with placeholders. Administrators **MUST** rotate the Google Client Secret immediately in the Google Cloud Console before deploying to staging or production environments.

### Key Guidelines:
1. **Never commit `.env` files** containing live production keys.
2. Ensure `/vault` directories inside Go node containers are mounted to encrypted host volumes or restricted block storage.
3. Node private identity keys (`identity.key`) and token signing keys (`saral_internal_token`) must only have read permissions restricted to the execution UID (`chmod 600`).
