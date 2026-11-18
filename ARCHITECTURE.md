# SARAL Protocol V3 — Architecture Specification

## 1. System Overview

SARAL V3 implements a tripartite separation-of-powers architecture across three independent administrative realms:

```text
                 REACT FRONTEND (Port 3000)
                            |
                     SARAL SDK CLIENT
                            |
                  AUTH SERVER (Port 3001)
                            |
                      JSON-RPC API
                            |
        +-------------------+-------------------+
        |                   |                   |
    FOUNDATION            PUBLIC              PRIVATE
    COORDINATOR        COORDINATOR          COORDINATOR
    (Port 9001)        (Port 9002)          (Port 9003)
        |                   |                   |
     VERIFIER            VERIFIER            VERIFIER
    (Port 9101)        (Port 9102)          (Port 9103)
        |                   |                   |
      NODE 1              NODE 1              NODE 1
      NODE 2              NODE 2              NODE 2
      NODE 3              NODE 3              NODE 3
      NODE 4              NODE 4              NODE 4
      NODE 5              NODE 5              NODE 5
        |                   |                   |
        +-------------------+-------------------+
                            |
                    P2P COMMUNICATION
                            |
                  CROSS-DOMAIN NETWORK
                            |
                 NETWORK STATUS / EVENTS
                            |
                       FRONTEND UI
```

---

## 2. Core Service Responsibilities

### 2.1 React Frontend (`apps/web`)
- Minimal, responsive network architecture dashboard.
- Real-time polling of Foundation, Public, and Private domain coordinators.
- Visualizes connected nodes, P2P link status, and peer counts.
- Orchestrates live authenticated network probes with visual latency and signature verification.

### 2.2 Auth Server (`apps/auth-server`)
- Minimal Node.js/TypeScript authentication microservice.
- Generates and manages RSA-2048 asymmetric key material.
- Exposes public keys via `/auth/public-key` and `/.well-known/jwks.json`.
- Issues signed RS256 Bearer JWTs with claims: `sub`, `iss`, `aud`, `exp`, `iat`, `domainRole`.

### 2.3 SARAL SDK (`packages/saral-sdk`)
- Lightweight typed JSON-RPC 2.0 client.
- Methods: `getNetworkStatus()`, `getDomainStatus()`, `getCoordinatorStatus()`, `getNodes()`, `getPeers()`, `getTopology()`, `probeNetwork()`.
- Zero private key custody in the SDK.

### 2.4 Domain Coordinators (`services/coordinator`)
- Deployed independently for Foundation, Public, and Private domains.
- Discovers local domain nodes and peer coordinators via background discovery monitor.
- Enforces request authorization via local Verifier.
- Handles cross-domain aggregation: coordinates probes across peer coordinators.
- JSON-RPC 2.0 endpoints for all protocol operations.

### 2.5 Domain Verifiers (`services/verifier`)
- Stateless Go verification microservice.
- Loads trusted RSA public key material from Auth Server or persistent volume.
- Fails closed if trust material is unavailable.
- Validates JWT token signatures, issuer, audience, and expiration.

### 2.6 SARAL Nodes (`services/saral-node`)
- Single reusable Go binary powering all 15 or 24 node instances.
- **Persistent Unique Identity:** Generates Ed25519 keypair and persistent Node ID on first boot; saves to vault directory with `0600` permissions.
- **P2P Mesh:** Periodically exchanges authenticated ping/pong heartbeats signed with Ed25519 keys.
- **Probe Handler:** Responds to network probes with signed acknowledgements, timestamps, and real latency measurements.

---

## 3. Communication & Authenticated Probe Flow

```text
1. User / Dashboard triggers "⚡ Run Network Probe" via SDK.
2. SDK sends saral_probeNetwork to Foundation Coordinator (:9001) with RS256 JWT.
3. Coordinator sends token to Verifier (:9101); Verifier confirms valid signature and claims.
4. Coordinator generates unique probeId and requestId.
5. Coordinator dispatches /node/probe concurrently to its 5 domain nodes.
6. Coordinator sends saral_probeDomain to Public Coordinator (:9002) and Private Coordinator (:9003).
7. Peer coordinators dispatch /node/probe to their respective domain nodes.
8. Each node receives the probe, computes latency, signs the probe confirmation with its Ed25519 private key, and returns an ACK.
9. Peer coordinators return domain probe results to the lead coordinator.
10. Lead coordinator aggregates all 15 probe acknowledgements and returns evidence to SDK and Dashboard.
```

---

## 4. Cryptographic Roadmap (Future Phases)

In compliance with Section 8 of the V3 specification, this release provides the clean architectural runtime. The following cryptographic modules are scheduled for subsequent implementation:

| Module | Status in V3 | Future Target |
| :--- | :--- | :--- |
| **P2P Mesh & Heartbeats** | **Operational** (Ed25519 Authenticated) | Production Mesh |
| **Token Authorization** | **Operational** (RS256 Asymmetric JWT) | Zero-Trust Token |
| **Network Probes & Discovery** | **Operational** (Cross-Domain Aggregation) | Continuous Health Engine |
| **Dealerless DKG** | *Future Phase* | Interactive Feldman/Pedersen VSS |
| **Threshold Signing (TSS)** | *Future Phase (Responds NOT_IMPLEMENTED)* | CGGMP21 with Paillier MtA |
| **FROST Schnorr / Taproot** | *Future Phase* | BIP-340 Compliant Signing |
| **EVM Transaction Broadcasting** | *Future Phase* | Multichain RPC Adapters |
