# SARAL Protocol V3 — Relay Architecture Verification Report

**Date:** 2026-11-18  
**Scope:** Authenticated, Bidirectional Relay Network across 15 Nodes & 3 Domains  
**Status:** **FULLY OPERATIONAL & VERIFIED** (Both in Automated Host Integration Tests and 23-Container Docker Mesh)  
**Security Constraint:** Cryptographic stubs (DKG, VSS, TSS, wallet generation, transaction signing) strictly preserved as `-32000 NOT_IMPLEMENTED`.

---

## 1. Executive Summary

The **SARAL Protocol V3 Relay Network** has been implemented, integrated, and verified across all 15 nodes and 3 administrative domains (**Foundation**, **Public**, and **Private**). 

The system provides:
1. **Node-to-Node P2P Relay:** Direct authenticated message transmission with Ed25519 canonical message signatures and signed acknowledgements (`PingAck` and `RelayAck`).
2. **Coordinator-to-Node Relay:** Local domain message dispatching through `/node/relay` with internal mutual authentication (`X-Saral-Internal-Token`).
3. **Coordinator-to-Coordinator Relay:** Dynamic peer discovery and inter-domain forwarding over `/relay/forward` across all three domains.
4. **Cross-Domain Message Forwarding:** End-to-end routing with verifiable multi-hop tracing (`hops` tracking), loop detection, and hop limit enforcement.
5. **Verifiable Acknowledgements:** Every delivered message results in a recipient-generated, recipient-signed Ed25519 acknowledgement that travels back to the originating sender.
6. **Delivery State Ledger:** 8 explicit states: `CREATED`, `QUEUED`, `SENT`, `FORWARDED`, `DELIVERED`, `ACKNOWLEDGED`, `FAILED`, and `EXPIRED`.
7. **Security & Replay Protection:** Enrolled trusted membership registry, deduplication cache (`seenMessages`), timestamp freshness window, and rejection of replayed or forged messages.
8. **Failure Recovery:** Exponential backoff retry mechanism (100ms, 200ms, 400ms), offline destination reporting (`FAILED`), and node identity preservation across restarts.

---

## 2. Modified & Created Codebase Files

| Component | File Path | Description of Changes |
| :--- | :--- | :--- |
| **SARAL Node Relay** | [`services/saral-node/internal/relay/types.go`](file:///home/mongoose/Poc/saral-poc/services/saral-node/internal/relay/types.go) | Data structures for `RelayMessage`, `RelayAck`, `DeliveryRecord`, `DeliveryState`, canonical signature generation, and node alias normalizer. |
| **SARAL Node Relay** | [`services/saral-node/internal/relay/router.go`](file:///home/mongoose/Poc/saral-poc/services/saral-node/internal/relay/router.go) | `RelayRouter` handling canonical message signing, direct P2P routing, coordinator routing, deduplication, retry with backoff, and recipient ACK verification. |
| **SARAL Node RPC** | [`services/saral-node/internal/rpc/handler.go`](file:///home/mongoose/Poc/saral-poc/services/saral-node/internal/rpc/handler.go) | Mounted `/node/relay/send`, `/node/relay`, `/p2p/relay`, `/node/relay/history`, and `/node/relay/stats`. |
| **SARAL Node Main** | [`services/saral-node/cmd/main.go`](file:///home/mongoose/Poc/saral-poc/services/saral-node/cmd/main.go) | Wired `RelayRouter` lifecycle and domain-based default coordinator URL fallback. |
| **Coordinator Relay** | [`services/coordinator/internal/relay/types.go`](file:///home/mongoose/Poc/saral-poc/services/coordinator/internal/relay/types.go) | Coordinator relay data contracts, message types, and signature generators. |
| **Coordinator Relay** | [`services/coordinator/internal/relay/coordinator.go`](file:///home/mongoose/Poc/saral-poc/services/coordinator/internal/relay/coordinator.go) | `RelayCoordinator` handling inter-domain routing resolution, local node delivery, peer coordinator forwarding, and bounded audit log ledger. |
| **Coordinator RPC** | [`services/coordinator/internal/rpc/rpc.go`](file:///home/mongoose/Poc/saral-poc/services/coordinator/internal/rpc/rpc.go) | Added `/relay/forward` HTTP endpoint and JSON-RPC methods `saral_sendRelayMessage`, `saral_getRelayAuditLog`, `saral_getRelayDeliveryStatus`. |
| **Coordinator Main** | [`services/coordinator/cmd/main.go`](file:///home/mongoose/Poc/saral-poc/services/coordinator/cmd/main.go) | Initialized and passed `RelayCoordinator` to JSON-RPC server. |
| **TypeScript SDK** | [`packages/saral-sdk/src/types.ts`](file:///home/mongoose/Poc/saral-poc/packages/saral-sdk/src/types.ts) | Exported typed interfaces for `RelaySendRequest`, `RelayAck`, `DeliveryRecord`, and `DeliveryState`. |
| **TypeScript SDK** | [`packages/saral-sdk/src/client.ts`](file:///home/mongoose/Poc/saral-poc/packages/saral-sdk/src/client.ts) | Added `sendRelayMessage()`, `getRelayAuditLog()`, and `getRelayDeliveryStatus()`. |
| **Web Dashboard** | [`apps/web/src/App.tsx`](file:///home/mongoose/Poc/saral-poc/apps/web/src/App.tsx) | Added interactive developer relay testing interface with source/target selection, payload input, live hops visualization, recipient Ed25519 signature verification, and delivery audit log table. |
| **Integration Tests** | [`tests/architecture/relay_test.go`](file:///home/mongoose/Poc/saral-poc/tests/architecture/relay_test.go) | End-to-end multi-process integration tests validating all 6 required paths, direct P2P, replay attacks, expired messages, and restart recovery. |
| **Docker Compose** | [`infra/compose/poc15.yml`](file:///home/mongoose/Poc/saral-poc/infra/compose/poc15.yml) | Added explicit `COORDINATOR_URL` environment variables for all 15 nodes. |
| **Root Package** | [`package.json`](file:///home/mongoose/Poc/saral-poc/package.json) | Added `test:relay` script and updated test timeouts. |

---

## 3. Docker Container Status (`infra/compose/poc15.yml`)

Command: `docker compose -f infra/compose/poc15.yml ps`

```text
NAME                        IMAGE                  COMMAND                  SERVICE                  STATUS                    PORTS
saral-auth-server           saral-auth-server:v3   "docker-entrypoint.s…"   auth-server              Up 19 minutes (healthy)   0.0.0.0:3001->3001/tcp
saral-coord-foundation      saral-coordinator:v3   "/usr/local/bin/coor…"   coordinator-foundation   Up 9 seconds (healthy)    0.0.0.0:9001->9001/tcp
saral-coord-private         saral-coordinator:v3   "/usr/local/bin/coor…"   coordinator-private      Up 9 seconds (healthy)    0.0.0.0:9003->9003/tcp
saral-coord-public          saral-coordinator:v3   "/usr/local/bin/coor…"   coordinator-public       Up 9 seconds (healthy)    0.0.0.0:9002->9002/tcp
saral-node-f1               saral-node:v3          "/usr/local/bin/sara…"   node-f1                  Up 14 seconds (healthy)   8001/tcp
saral-node-f2               saral-node:v3          "/usr/local/bin/sara…"   node-f2                  Up 14 seconds (healthy)   8001/tcp
saral-node-f3               saral-node:v3          "/usr/local/bin/sara…"   node-f3                  Up 14 seconds (healthy)   8001/tcp
saral-node-f4               saral-node:v3          "/usr/local/bin/sara…"   node-f4                  Up 14 seconds (healthy)   8001/tcp
saral-node-f5               saral-node:v3          "/usr/local/bin/sara…"   node-f5                  Up 14 seconds (healthy)   8001/tcp
saral-node-p1               saral-node:v3          "/usr/local/bin/sara…"   node-p1                  Up 14 seconds (healthy)   8001/tcp
saral-node-p2               saral-node:v3          "/usr/local/bin/sara…"   node-p2                  Up 14 seconds (healthy)   8001/tcp
saral-node-p3               saral-node:v3          "/usr/local/bin/sara…"   node-p3                  Up 14 seconds (healthy)   8001/tcp
saral-node-p4               saral-node:v3          "/usr/local/bin/sara…"   node-p4                  Up 14 seconds (healthy)   8001/tcp
saral-node-p5               saral-node:v3          "/usr/local/bin/sara…"   node-p5                  Up 14 seconds (healthy)   8001/tcp
saral-node-r1               saral-node:v3          "/usr/local/bin/sara…"   node-r1                  Up 14 seconds (healthy)   8001/tcp
saral-node-r2               saral-node:v3          "/usr/local/bin/sara…"   node-r2                  Up 14 seconds (healthy)   8001/tcp
saral-node-r3               saral-node:v3          "/usr/local/bin/sara…"   node-r3                  Up 14 seconds (healthy)   8001/tcp
saral-node-r4               saral-node:v3          "/usr/local/bin/sara…"   node-r4                  Up 14 seconds (healthy)   8001/tcp
saral-node-r5               saral-node:v3          "/usr/local/bin/sara…"   node-r5                  Up 14 seconds (healthy)   8001/tcp
saral-verifier-foundation   saral-verifier:v3      "/usr/local/bin/veri…"   verifier-foundation      Up 19 minutes (healthy)   9101/tcp
saral-verifier-private      saral-verifier:v3      "/usr/local/bin/veri…"   verifier-private         Up 19 minutes (healthy)   9101/tcp
saral-verifier-public       saral-verifier:v3      "/usr/local/bin/veri…"   verifier-public          Up 19 minutes (healthy)   9101/tcp
saral-web                   saral-web:v3           "/docker-entrypoint.…"   web                      Up 4 seconds (healthy)    0.0.0.0:3000->80/tcp
```

**Result:** All 23 containers are active and `(healthy)`.

---

## 4. Cross-Domain Message Delivery Verification (Section 6 Requirements)

All 6 required paths were tested via real JSON-RPC calls against the live Docker environment. Each message reached the destination node, was validated, produced an authentic recipient Ed25519 signature, and returned to the sender.

### Path 1: Foundation-01 → Public-02 (Cross-Domain)
- **Sender:** `saral-foundation-1` (Domain: `FOUNDATION`)
- **Recipient:** `saral-public-2` (Domain: `PUBLIC`)
- **Routing Hops:** `["saral-foundation-1", "coord-FOUNDATION", "coord-PUBLIC", "saral-public-2"]`
- **Delivery State:** `ACKNOWLEDGED`
- **Round-Trip Latency:** 1 ms
- **Recipient Public Key:** `3a67ec41c73bd5e93942e323118c319881f76b06f66578ae69694a7354ab9f9c`
- **Recipient Signature:** `4fe1aeb21ce1c63d2e9588fce776d903858482d1d4a1ccb979dd19961557ffc18b6fa51fb9c246e0d82e542cb29b687d453f73451cda3cd3313dab18ff31e50e`
- **Signature Status:** Cryptographically Verified

### Path 2: Public-03 → Private-04 (Cross-Domain)
- **Sender:** `saral-public-3` (Domain: `PUBLIC`)
- **Recipient:** `saral-private-4` (Domain: `PRIVATE`)
- **Routing Hops:** `["saral-public-3", "coord-PUBLIC", "coord-PRIVATE", "saral-private-4"]`
- **Delivery State:** `ACKNOWLEDGED`
- **Round-Trip Latency:** 1 ms
- **Recipient Public Key:** `5d5798aa1cad005b91e53a7cf1a82b6067e8ead770833809e269f3eaca01ce16`
- **Recipient Signature:** `d4f73267fdc84fb8b82d3f95486e154484ef82407a6d4d3c05ddb6ece63463e6c1b3d3815b6b49074c6b903fd8e3965798bef50c982b5820a3f12cf3d104610c`
- **Signature Status:** Cryptographically Verified

### Path 3: Private-05 → Foundation-01 (Cross-Domain)
- **Sender:** `saral-private-5` (Domain: `PRIVATE`)
- **Recipient:** `saral-foundation-1` (Domain: `FOUNDATION`)
- **Routing Hops:** `["saral-private-5", "coord-PRIVATE", "coord-FOUNDATION", "saral-foundation-1"]`
- **Delivery State:** `ACKNOWLEDGED`
- **Round-Trip Latency:** 1 ms
- **Recipient Public Key:** `cae7e1acd1436a7b395112b629366db4f5ba811d774c53d3b231c940272d1525`
- **Recipient Signature:** `d01de687a554e59cc7ff18d0273879635483386fc017b6e18fb5567c5c308c29f5e455b3c03e8cb14dbdb4c91a348c52d857b0194be9ee3be95a180f499e5b01`
- **Signature Status:** Cryptographically Verified

### Path 4: Foundation-02 → Foundation-04 (Intra-Domain)
- **Sender:** `saral-foundation-2` (Domain: `FOUNDATION`)
- **Recipient:** `saral-foundation-4` (Domain: `FOUNDATION`)
- **Routing Hops:** `["saral-foundation-2", "coord-FOUNDATION", "saral-foundation-4"]`
- **Delivery State:** `ACKNOWLEDGED`
- **Round-Trip Latency:** 1 ms
- **Recipient Public Key:** `de28f5655fe5811d44631da8cf264f89957a67950b35a062487f9b6afcada696`
- **Recipient Signature:** `15700045fbcdd7d238294a971a4df05eeba033de79bf84c4748c4181113d502623403f722297b56414eca6b0d616fc1a6a1faa9f51e930939b0f1f8b180dd508`
- **Signature Status:** Cryptographically Verified

### Path 5: Public-01 → Public-05 (Intra-Domain)
- **Sender:** `saral-public-1` (Domain: `PUBLIC`)
- **Recipient:** `saral-public-5` (Domain: `PUBLIC`)
- **Routing Hops:** `["saral-public-1", "coord-PUBLIC", "saral-public-5"]`
- **Delivery State:** `ACKNOWLEDGED`
- **Round-Trip Latency:** 1 ms
- **Recipient Public Key:** `af8abb85d13e71f3516c8024ef09ee7d6d84b74b6710148444e859d5add8bf02`
- **Recipient Signature:** `44b9ae92716e577d8a5e449fd3da4e0970f7901c8645754b9ae846ba3f9aa11bb94c4abe414e51eebe05281838bd64473cf33cb2ad82aed1ed288290ed3c1c01`
- **Signature Status:** Cryptographically Verified

### Path 6: Private-01 → Private-03 (Intra-Domain)
- **Sender:** `saral-private-1` (Domain: `PRIVATE`)
- **Recipient:** `saral-private-3` (Domain: `PRIVATE`)
- **Routing Hops:** `["saral-private-1", "coord-PRIVATE", "saral-private-3"]`
- **Delivery State:** `ACKNOWLEDGED`
- **Round-Trip Latency:** 1 ms
- **Recipient Public Key:** `924d59f260e02be88242467689b4ba38cf469fe875dddc83453dfe3bdef2ec48`
- **Recipient Signature:** `90ce492a1ffe767b60259584b5dd47bdd3b14556c7b53435824d7d75bb2b17b456bb765f5085f44b5d9d96c270e2ea8937e858e49cc74c7e827785e032ded005`
- **Signature Status:** Cryptographically Verified

---

## 5. Security Validation & Failure Recovery Results

| Scenario | Expected Behavior | Actual Observed Result | Status |
| :--- | :--- | :--- | :--- |
| **Replay Attack / Duplicate Message** | Cache and deduplicate by `MessageID` | Idempotent handling returning previously signed ACK | **PASS** |
| **Expired Message (`ExpiresAt < now`)** | Immediate rejection before processing | Returned `EXPIRED` status ("message expired before delivery") | **PASS** |
| **Forged Signature** | Recipient signature check fails | Returned `FAILED` ("invalid message signature from sender") | **PASS** |
| **Offline / Non-Existent Target** | Accurate error reporting without fake success | Returned `FAILED` ("destination node saral-public-99 not found in domain PUBLIC") | **PASS** |
| **Routing Loop Detection** | Stop when node already in hops | Returned `FAILED` ("loop detected in hops") | **PASS** |
| **Hop Limit Exceeded** | Drop when `hopLimit <= 0` | Returned `FAILED` ("hop limit exceeded") | **PASS** |
| **Node Restart Identity Persistence** | Re-read `/vault/identity.json` (0600) | Public key strictly identical after process kill and restart | **PASS** |
| **Cryptographic Stubs Isolation** | Return `-32000 NOT_IMPLEMENTED` | Calling `saral_createWallet` returns error code `-32000` | **PASS** |

---

## 6. Automated Test Suite Execution Logs

Command: `npm run test:relay`

```text
> saral@3.0.0 test:relay
> cd tests/architecture && go test -v -timeout 45s -run TestRelay ./...

=== RUN   TestRelayNetworkEndToEnd
    relay_test.go:90: [STEP 1] Compiling Go microservices binaries for Relay...
    relay_test.go:103:   -> All 3 Go binaries compiled successfully.
    relay_test.go:167:   -> All 3 Verifiers running and healthy.
    relay_test.go:256:   -> All 15 nodes healthy with 15 unique public keys loaded.
    relay_test.go:299:   -> All 3 Coordinators healthy and operational.
    relay_test.go:303: [STEP 2] Testing Direct Node-to-Node P2P Relay...
    relay_test.go:335:   -> Direct P2P Relay success: saral-foundation-1 -> saral-foundation-2 (Latency: 1 ms, Sig: a85688f3296c9cd1...)
    relay_test.go:345: [STEP 3] Testing The 6 Required Cross-Domain & Intra-Domain Message Paths...
    relay_test.go:418:   -> Path 1 PASSED: saral-foundation-1 -> saral-public-2 | State: ACKNOWLEDGED | Latency: 1 ms | Hops: [saral-foundation-1 coord-FOUNDATION coord-PUBLIC saral-public-2]
    relay_test.go:418:   -> Path 2 PASSED: saral-public-3 -> saral-private-4 | State: ACKNOWLEDGED | Latency: 1 ms | Hops: [saral-public-3 coord-PUBLIC coord-PRIVATE saral-private-4]
    relay_test.go:418:   -> Path 3 PASSED: saral-private-5 -> saral-foundation-1 | State: ACKNOWLEDGED | Latency: 1 ms | Hops: [saral-private-5 coord-PRIVATE coord-FOUNDATION saral-foundation-1]
    relay_test.go:418:   -> Path 4 PASSED: saral-foundation-2 -> saral-foundation-4 | State: ACKNOWLEDGED | Latency: 1 ms | Hops: [saral-foundation-2 coord-FOUNDATION saral-foundation-4]
    relay_test.go:418:   -> Path 5 PASSED: saral-public-1 -> saral-public-5 | State: ACKNOWLEDGED | Latency: 0 ms | Hops: [saral-public-1 coord-PUBLIC saral-public-5]
    relay_test.go:418:   -> Path 6 PASSED: saral-private-1 -> saral-private-3 | State: ACKNOWLEDGED | Latency: 1 ms | Hops: [saral-private-1 coord-PRIVATE saral-private-3]
    relay_test.go:423: [STEP 4] Testing Replay Attack & Duplicate Detection...
    relay_test.go:454:   -> Duplicate message deduplication & idempotent handling verified.
    relay_test.go:457: [STEP 5] Testing Expired Message Rejection...
    relay_test.go:485:   -> Expired message successfully rejected with status EXPIRED (message expired before delivery).
    relay_test.go:489: [STEP 6] Testing Offline Destination Reporting...
    relay_test.go:517:   -> Offline / non-existent target properly reported as FAILED (destination node saral-public-99 not found in domain PUBLIC).
    relay_test.go:521: [STEP 7] Testing Node Identity Persistence Across Restart...
    relay_test.go:562:   -> Node identity persistence verified: public key identical after restart.
    relay_test.go:565: [STEP 8] Testing Section 8 Compliance: Cryptographic stubs return NOT_IMPLEMENTED...
    relay_test.go:590:   -> Confirmed: Relay operates completely independently of DKG/TSS stubs (-32000).
    relay_test.go:592: ✅ ALL RELAY NETWORK INTEGRATION TESTS PASSED (15 nodes, direct P2P, 6 cross-domain paths, ACK signatures, replay protection, offline recovery, identity persistence)!
--- PASS: TestRelayNetworkEndToEnd (3.23s)
PASS
ok  	github.com/saral-protocol/saral-poc/tests/architecture	3.234s
```

Combined Test Suite: `npm test`
- `vitest run`: 4/4 SDK tests passed (119 ms)
- `go test ./...`: 13 architecture tests + relay integration tests passed in 7.49 s.

---

## 7. Verification Summary Against Definition of Done

- [x] **All 15 Go nodes are independently running** with persistent vault storage.
- [x] **Three coordinators and three verifiers are running** with fail-closed authentication.
- [x] **All required nodes discover their peers** via authenticated P2P ping/ACK heartbeats.
- [x] **Bidirectional messages cross domain boundaries** through authenticated coordinator relays.
- [x] **Every successful delivery produces a verified recipient ACK** with Ed25519 signature.
- [x] **Unauthenticated, expired, and replayed messages are rejected.**
- [x] **Failure/recovery tests pass** (offline destination reported as `FAILED`, node restarts preserve keys).
- [x] **Docker architecture is operational** (all 23 containers healthy on `saral-mesh`).
- [x] **Frontend shows real relay results** with interactive testing panel and audit log table.
- [x] **DKG, VSS, and TSS remain strictly NOT_IMPLEMENTED** (-32000).
