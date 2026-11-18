# SARAL Protocol V3 — Operations & Runbook Manual

This guide provides operational instructions for compiling, deploying, inspecting, and troubleshooting SARAL Protocol V3 in both 15-node POC and 24-node Production topologies.

---

## 1. Building the System

### Clean Build
```bash
# Clean previous build artifacts
npm run clean

# Build all Go binaries, SDK packages, and Web frontend
npm run build
```

Expected build artifacts:
- `services/coordinator/bin/coordinator`
- `services/verifier/bin/verifier`
- `services/saral-node/bin/saral-node`
- `packages/saral-sdk/dist/`
- `apps/auth-server/dist/`
- `apps/web/dist/`

---

## 2. Deploying with Docker Compose

### 2.1 Starting the 15-Node POC (23 Containers)
```bash
# Start all 15 nodes, 3 coordinators, 3 verifiers, auth server, and web frontend
npm run docker:poc
# OR
docker compose -f infra/compose/poc15.yml up --build -d
```

### 2.2 Starting the 24-Node Production (32 Containers)
```bash
npm run docker:full
# OR
docker compose -f infra/compose/full24.yml up --build -d
```

### 2.3 Checking Deployment Status
```bash
npm run docker:status
# OR
docker compose -f infra/compose/poc15.yml ps
```

All containers should report `Up` with healthy status.

---

## 3. Inspecting Logs & P2P Connections

### 3.1 Viewing Node Logs
```bash
# View live logs for Foundation Node 1
docker logs -f saral-node-f1

# View logs for Public Coordinator
docker logs -f saral-coord-public

# View logs for Auth Server
docker logs -f saral-auth-server
```

### 3.2 Inspecting Connected Peers on a Node
Each node exposes its real-time P2P peer table:
```bash
# Query node-f1 internal peer status
docker exec saral-node-f1 wget -qO- http://localhost:8001/node/status
# OR via host if port mapped:
curl -s http://localhost:8001/node/peers
```

Sample output:
```json
{
  "nodeId": "saral-foundation-1",
  "domain": "FOUNDATION",
  "connectedPeers": 3,
  "totalPeers": 3,
  "status": "ACTIVE",
  "peers": [
    { "endpoint": "http://node-f2:8001", "nodeId": "saral-foundation-2", "connected": true, "latencyMs": 1 },
    { "endpoint": "http://node-p1:8001", "nodeId": "saral-public-1", "connected": true, "latencyMs": 2 },
    { "endpoint": "http://node-r1:8001", "nodeId": "saral-private-1", "connected": true, "latencyMs": 2 }
  ]
}
```

---

## 4. Triggering Probes via JSON-RPC CLI

You can trigger a real network probe directly from the terminal:

```bash
# 1. Fetch Auth Token
TOKEN=$(curl -s -X POST http://localhost:3001/auth/token -H "Content-Type: application/json" -d '{"subject":"cli-admin"}' | grep -o '"token":"[^"]*' | cut -d'"' -f4)

# 2. Dispatch Network Probe to Coordinator (:9001)
curl -s -X POST http://localhost:9001/rpc \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"saral_probeNetwork","params":{}}' | jq .
```

---

## 5. Troubleshooting & Failure Recovery

### Problem: Node Unreachable
If a node fails or crashes:
```bash
# 1. Check container exit code
docker ps -a --filter "name=saral-node"

# 2. Restart specific container
docker restart saral-node-f3

# 3. Verify coordinator re-discovers the node
curl -s -X POST http://localhost:9001/rpc -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"saral_getDomainStatus","params":{}}' | jq .
```

### Problem: Missing Trust Material on Verifier
If verifier reports `not_ready` on `/health`:
- Ensure `auth-server` is running and healthy.
- Check `docker logs saral-verifier-foundation` to confirm it reached `http://auth-server:3001/auth/public-key`.

---

## 6. Stopping & Cleaning Up

```bash
# Stop all containers (preserves volume data)
npm run docker:down

# To completely purge named volumes and reset identities:
docker compose -f infra/compose/poc15.yml down -v
```

---

## 7. Backing Up Node Identity Volumes

Node identities and Ed25519 public/private keys are stored inside named Docker volumes:
```text
node_f1_vault .. node_f5_vault (Foundation)
node_p1_vault .. node_p5_vault (Public)
node_r1_vault .. node_r5_vault (Private)
```

To backup node identity files to host:
```bash
docker run --rm -v saral-poc_node_f1_vault:/vault -v $(pwd):/backup alpine tar czf /backup/node_f1_identity.tar.gz -C /vault .
```
