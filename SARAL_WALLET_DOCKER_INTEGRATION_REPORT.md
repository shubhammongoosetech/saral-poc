# SARAL Protocol V3 — Docker Mesh Network & Container Integration Report

**Date:** November 19, 2026  
**Auditor:** Docker Infrastructure & Distributed Systems Engineer  
**Compose File:** `infra/compose/poc15.yml`  
**Total Containers:** 23 (All Running & Healthy)

---

## 1. Container Topology & Health Status

| Service Name | Container Name | Port Mapping | Healthcheck Endpoint | Status |
| :--- | :--- | :--- | :--- | :--- |
| `web` | `saral-web` | `0.0.0.0:3000->80/tcp` | `wget -q http://localhost:80` | **Healthy** |
| `auth-server` | `saral-auth-server` | `0.0.0.0:3001->3001/tcp` | `wget -q http://localhost:3001/health` | **Healthy** |
| `coordinator-foundation` | `saral-coord-foundation` | `9001:9001, 9443:9443` | `wget -q http://localhost:9001/health` | **Healthy** |
| `coordinator-public` | `saral-coord-public` | `9002:9002, 9444:9443` | `wget -q http://localhost:9002/health` | **Healthy** |
| `coordinator-private` | `saral-coord-private` | `9003:9003, 9445:9443` | `wget -q http://localhost:9003/health` | **Healthy** |
| `verifier-foundation` | `saral-verifier-foundation`| `9101/tcp` | `wget -q http://localhost:9101/health` | **Healthy** |
| `verifier-public` | `saral-verifier-public` | `9101/tcp` | `wget -q http://localhost:9101/health` | **Healthy** |
| `verifier-private` | `saral-verifier-private` | `9101/tcp` | `wget -q http://localhost:9101/health` | **Healthy** |
| `node-f1..f5` (5 Nodes) | `saral-node-f1..f5` | `8001, 8443` | `wget -q http://localhost:8001/node/status` | **Healthy** |
| `node-p1..p5` (5 Nodes) | `saral-node-p1..p5` | `8001, 8443` | `wget -q http://localhost:8001/node/status` | **Healthy** |
| `node-r1..r5` (5 Nodes) | `saral-node-r1..r5` | `8001, 8443` | `wget -q http://localhost:8001/node/status` | **Healthy** |

---

## 2. Node Vault Inspection & Volume Persistence

SARAL Go nodes store encrypted secret polynomial shares inside local vaults at `/vault`. Each node has an independent Docker named volume (e.g. `node_f1_vault`, `node_p1_vault`, `node_r1_vault`).

```powershell
# Command:
docker exec saral-node-f1 ls -la /vault

# Verified Container Output:
total 16
drwxr-xr-x    2 root     root          4096 Nov 18 16:50 .
drwxr-xr-x    1 root     root          4096 Nov 18 19:34 ..
-rw-------    1 root     root           543 Nov 18 16:35 identity.json
-rw-------    1 root     root             2 Nov 18 19:02 seen_relay_messages.json
```

---

## 3. Web & Auth Server Reverse Proxy Routing

Nginx routes requests dynamically across the mesh:
1. `GET /` $\to$ Returns the compiled Single Page Application (`apps/web/dist/index.html`).
2. `POST /auth/*` $\to$ Proxied internally to `http://auth-server:3001/auth/*`.
3. `POST /wallet/*` $\to$ Proxied internally to `http://auth-server:3001/wallet/*`.
4. `POST /rpc` $\to$ Proxied internally to `http://coordinator-foundation:9001`.
5. `GET /sw.js` $\to$ Intercepted with an immediate auto-unregistration script to safely clear legacy browser service workers.

---

## 4. Operational Commands

```powershell
# Check running status of all 23 containers:
npm run docker:status

# Start or restart the Docker cluster:
npm run docker:poc

# Stop the Docker cluster:
npm run docker:down
```
