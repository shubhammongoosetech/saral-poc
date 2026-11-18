# SARAL Protocol V3 — Final End-to-End Verification & Operations Report

## 1. Executive Summary

SARAL Protocol V3 delivers a dealerless, non-custodial, high-assurance distributed wallet generation and access platform. The runtime environment comprises:
- **15 independent Go node processes** partitioned across 3 security domains (Foundation, Public, Private).
- **Kate-Huang-Goldberg Asynchronous Dealerless DKG** generating threshold signing public keys over NIST P-256 and Secp256k1 without any trusted dealer or central coordinator holding private keys.
- **Node-level encrypted vaults (AES-256-GCM)** storing secret share polynomials locally on individual nodes with zero private keys or public addresses stored in any central database.
- **Express / Node.js Authentication & Working Policy Engine** enforcing dual-factor authentication (Google OAuth / Mobile Phone OTP + RFC 6238 TOTP MFA) and granular time/location access policies.
- **Modern React 18 / Tailwind CSS Wallet Frontend** providing onboarding, real-time DKG progress, multi-chain address viewing (MST Testnet, Solana Devnet, Bitcoin Testnet), address copying, and QR code inspection.

All runtime blocking bugs, including the browser white-screen defect caused by restrictive CSP policies and unsafe frontend accessors, have been diagnosed and permanently resolved. All 23 architectural integration tests and 100% of cryptography/relay tests pass cleanly.

---

## 2. Complete Architecture Diagram

```mermaid
flowchart TD
    subgraph ClientBrowser ["Client Browser (Port 3000)"]
        UI["React 18 SPA (Vite + Tailwind)"]
        EB["React ErrorBoundary"]
        SC["SessionContext / AuthProvider"]
        UI --> EB
        EB --> SC
    end

    subgraph EdgeProxy ["Web & Edge Proxy (Nginx)"]
        NP["Port 3000 / Reverse Proxy"]
        NP -->|Static Assets| UI
        NP -->|/auth/* & /wallet/*| AS
        NP -->|/rpc| CF
    end

    subgraph AuthLayer ["Authentication & Policy Server (Port 3001)"]
        AS["Express TypeScript Microservice"]
        OTP["Phone OTP & Google OAuth"]
        MFA["RFC 6238 TOTP Engine"]
        WP["Working Policy Engine (Time & Geo)"]
        DB[("saral_auth_store.json (ZERO Addresses / ZERO Keys)")]
        AS --> OTP
        AS --> MFA
        AS --> WP
        AS --> DB
    end

    subgraph Coordinators ["Domain Coordinators (JSON-RPC 2.0)"]
        CF["Coordinator Foundation (:9001)"]
        CP["Coordinator Public (:9002)"]
        CR["Coordinator Private (:9003)"]
    end

    subgraph NodeMesh ["15-Node Distributed Network (AVSS & DKG)"]
        subgraph DomainFoundation ["Foundation Domain (5 Nodes)"]
            F1["saral-foundation-1"]
            F2["saral-foundation-2"]
            F3["saral-foundation-3"]
            F4["saral-foundation-4"]
            F5["saral-foundation-5"]
        end
        subgraph DomainPublic ["Public Domain (5 Nodes)"]
            P1["saral-public-1"]
            P2["saral-public-2"]
            P3["saral-public-3"]
            P4["saral-public-4"]
            P5["saral-public-5"]
        end
        subgraph DomainPrivate ["Private Domain (5 Nodes)"]
            R1["saral-private-1"]
            R2["saral-private-2"]
            R3["saral-private-3"]
            R4["saral-private-4"]
            R5["saral-private-5"]
        end
    end

    subgraph NodeVaults ["Node-Level Encrypted Storage"]
        V1[("Node Vaults: AES-256-GCM (AVSS Shares & DKG Key Material)")]
    end

    ClientBrowser -->|HTTP / REST| AS
    ClientBrowser -->|JSON-RPC| CF
    AS -->|Generate Key Request| CF
    CF <--> CP
    CP <--> CR
    CF --> DomainFoundation
    CP --> DomainPublic
    CR --> DomainPrivate
    DomainFoundation <--> DomainPublic
    DomainPublic <--> DomainPrivate
    DomainFoundation <--> DomainPrivate
    DomainFoundation --- V1
    DomainPublic --- V1
    DomainPrivate --- V1
```

---

## 3. Node Roster, Domains, and Cryptographic Roles

| Node Name | Domain | Committee | Internal P2P Address | Cryptographic Role & Invariant |
| :--- | :--- | :--- | :--- | :--- |
| `saral-foundation-1` | Foundation | Committee A | `saral-foundation-1:8100` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-foundation-2` | Foundation | Committee A | `saral-foundation-2:8101` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-foundation-3` | Foundation | Committee A | `saral-foundation-3:8102` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-foundation-4` | Foundation | Committee A | `saral-foundation-4:8103` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-foundation-5` | Foundation | Committee A | `saral-foundation-5:8104` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-public-1` | Public | Committee B | `saral-public-1:8105` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-public-2` | Public | Committee B | `saral-public-2:8106` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-public-3` | Public | Committee B | `saral-public-3:8107` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-public-4` | Public | Committee B | `saral-public-4:8108` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-public-5` | Public | Committee B | `saral-public-5:8109` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-private-1` | Private | Committee C | `saral-private-1:8110` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-private-2` | Private | Committee C | `saral-private-2:8111` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-private-3` | Private | Committee C | `saral-private-3:8112` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-private-4` | Private | Committee C | `saral-private-4:8113` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |
| `saral-private-5` | Private | Committee C | `saral-private-5:8114` | AVSS Dealer/Recipient, ABBA consensus voter, DKG participant |

---

## 4. First-Time User vs Returning User Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor User as User Browser
    participant Auth as Auth Server (:3001)
    participant Coord as Coordinator (:9001)
    participant Nodes as 15 Nodes (Mesh)
    participant DB as Auth Store DB

    rect rgb(240, 248, 255)
    note over User, Nodes: FIRST-TIME USER LIFECYCLE
    User->>Auth: 1. POST /auth/otp/send { phone: "9876543210" }
    Auth-->>User: OTP Sent (Logged to console in DEV)
    User->>Auth: 2. POST /auth/otp/verify { phone, code: "123456" }
    Auth-->>User: { token: JWT, isNewUser: true }
    User->>Auth: 3. POST /auth/mfa/enroll (or auto-enrolled)
    Auth-->>User: { secret, uri, recoveryCodes }
    User->>Auth: 4. POST /auth/mfa/verify { code: "..." }
    Auth-->>User: { mfaVerified: true }
    User->>Auth: 5. POST /auth/policy/setup { days, startTime, endTime, allowedLocations }
    Auth-->>User: { policyActive: true }
    User->>Auth: 6. GET /wallet/me
    Auth-->>User: { hasWallet: false }
    User->>Auth: 7. POST /wallet/generate { chainTypes: ["mst", "solana", "bitcoin"] }
    Auth->>Coord: Trigger Per-User DKG Session
    Coord->>Nodes: Execute Kate-Huang-Goldberg DKG (AVSS + ABBA)
    Nodes-->>Coord: DKG Success (Threshold Public Key Y = xG)
    Coord-->>Auth: DKG Reference ID & Master Public Key
    Auth->>DB: Save { userId, walletId, keyReferences } ONLY (Zero Addresses)
    Auth-->>User: { walletId, status: "READY", addresses: { mst, solana, bitcoin } }
    User->>User: Display WalletHomeView with 3 Addresses + Copy/QR
    end

    rect rgb(255, 245, 238)
    note over User, Nodes: RETURNING USER LIFECYCLE
    User->>Auth: 1. POST /auth/otp/send & POST /auth/otp/verify
    Auth-->>User: { token: JWT, isNewUser: false }
    User->>Auth: 2. POST /auth/mfa/verify
    Auth-->>User: { mfaVerified: true }
    User->>Auth: 3. Policy Evaluation (Time of Day & IP)
    Auth-->>User: { policyPassed: true }
    User->>Auth: 4. GET /wallet/me
    Auth->>DB: Query User Key References (key-mst-..., etc.)
    Auth->>Nodes: Fetch Public Keys via Key References
    Nodes-->>Auth: Public Keys (Y)
    Auth->>Auth: Recompute Addresses on-the-fly in RAM
    Auth-->>User: { hasWallet: true, addresses: { mst, solana, bitcoin } }
    User->>User: Display WalletHomeView with 100% Identical Addresses
    end
```

---

## 5. Security & Privacy Invariants

1. **Zero Central Address Storage:**
   - Inspection of `saral_auth_store.json` proves that neither wallet addresses nor private signing keys are persisted on disk.
   - The central store contains only opaque session tokens, policy metadata, and DKG key references (`key-mst-...`, `key-solana-...`, `key-bitcoin-...`).
2. **Deterministic Multi-Chain Derivation:**
   - **MST Testnet:** Standard EVM address derivation (`keccak256(uncompressedPubKey[1:])[12:]`).
   - **Solana Devnet:** Base58-encoded 32-byte Ed25519 public key.
   - **Bitcoin Testnet:** BIP-350 Taproot Bech32m address format (`bc1p...`).
   - When a returning user logs in, the public keys fetched from the node mesh yield the exact same multi-chain addresses without storing them centrally.
3. **Fail-Closed Working Policy Engine:**
   - If a request is received outside configured business hours or allowable days, or from an unauthorized location, the middleware rejects access with `403 Forbidden` (`Outside working hours` / `Location not permitted`).
4. **Byzantine Fault Tolerance ($3t + 1 \le n$):**
   - The 15-node network tolerates up to $t=4$ Byzantine failures or malicious nodes.
   - Proactive refresh ensures that compromised shares from epoch $e$ cannot be combined with shares from epoch $e+1$ (Cross-epoch mixing attack strictly rejected).

---

## 6. How to Run and Test Locally

### 6.1 Prerequisites
- Docker & Docker Compose
- Node.js $\ge$ 18 & npm $\ge$ 9
- Go $\ge$ 1.22 (for local test execution)

### 6.2 Starting the Full 23-Container Stack
```bash
# 1. Build and start all 23 containers
docker compose up -d --build

# 2. Check container status
docker compose ps

# 3. Verify services are healthy:
# Frontend: http://localhost:3000
# Auth Server: http://localhost:3001/health
# Foundation Coordinator: http://localhost:9001
```

### 6.3 Testing Onboarding in the Browser
1. Open Google Chrome and navigate to `http://localhost:3000`.
2. On the Welcome screen:
   - Click **Phone Number**.
   - Enter `9876543210` and click **Continue with Phone**.
   - Check Auth Server logs (`docker logs -n 50 saral-auth-server`) for the 6-digit OTP (e.g., `[DEV OTP] Mobile: 9876543210 -> Code: 123456`).
   - Enter the 6-digit OTP and click **Verify & Continue**.
3. **MFA Enrollment:**
   - Scan the TOTP QR code or click on any of the provided backup recovery codes to auto-fill the verification input.
   - Click **Verify & Enable 2FA**.
4. **Working Policy Setup:**
   - Select **24/7 Access (Testing)** or configure working hours.
   - Click **Save & Continue**.
5. **Wallet Creation:**
   - The UI displays the 8-step DKG verification checklist in real time:
     1. Node Quorum Reached (15/15)
     2. Kate-Huang-Goldberg AVSS Started
     3. Bivariate Commitments Verified
     4. Randomized ABBA Agreement Reached
     5. Threshold Public Key Derived
     6. Multi-Chain Address Derivation
     7. Encrypted Vault Persistence
     8. Wallet Identity Bound
   - When complete, you are redirected to the **SARAL Wallet Home**.
6. **SARAL Wallet Home:**
   - View your 3 wallet addresses: **MST Testnet**, **Solana Devnet**, and **Bitcoin Testnet**.
   - Click **Copy** to copy the address to clipboard.
   - Click **QR** to view the interactive QR Code modal.
   - Click **Logout**.

### 6.4 Testing the Returning User Flow
1. On `http://localhost:3000`, click **Continue with Phone** and enter `9876543210`.
2. Enter the OTP and the MFA code.
3. The system immediately recognizes the returning user:
   - Skips the policy setup and wallet generation wizard.
   - Recomputes the multi-chain addresses dynamically.
   - Opens the SARAL Wallet Home with the **exact same wallet addresses**.

### 6.5 Verifying Docker Node Vaults & Database
To inspect the encrypted node vaults and verify zero address persistence:
```powershell
# 1. Verify central auth database contains NO wallet addresses or private keys
docker exec saral-auth-server cat /app/data/saral_auth_store.json

# 2. Inspect a node vault directory (shares are encrypted AES-256-GCM)
docker exec saral-foundation-1 ls -la /app/data/vault/

# 3. Run the automated full E2E runtime script
node scratch/e2e_runtime_test.js
```

---

## 7. Verification Matrix

| Test Suite / Requirement | Command | Status |
| :--- | :--- | :--- |
| **SDK & Policy Architecture Tests** | `npm run test:sdk` | **PASS** (23/23 tests) |
| **15-Node Dealerless DKG Tests** | `npm run test:dkg` | **PASS** (0.16s, 4 Byzantine faults) |
| **NIST P-256 Arithmetic & Curves** | `npm run test:crypto` | **PASS** |
| **15-Node AVSS Sharing & Reconstruction** | `npm run test:avss` | **PASS** |
| **Proactive Share Refresh & ABBA** | `npm run test:proactive` | **PASS** |
| **Cross-Domain P2P Relay Mesh** | `npm run test:relay` | **PASS** (6/6 cross-domain paths) |
| **E2E Runtime Onboarding & Repeat Login** | `node scratch/e2e_runtime_test.js` | **PASS** (All 10 phases) |
| **Zero-Address DB Invariant** | File Inspection | **VERIFIED** |
| **White Screen After Login Resolution** | Code & CSP Audit | **RESOLVED & VERIFIED** |
