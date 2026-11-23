# SARAL POC — DKG Reference Implementation Integration Guide
*Architecture: 2-Component Decentralized DKG (Web2 Auth + 15 SARAL Nodes)*

---

## 1. Reference Implementation Analysis (Reference mein kya hai)

Is project mein reference implementation **Kate-Huang-Goldberg (ACNS 2012 / ePrint 2012/377)** aur **Cachin et al. (Dual-Threshold AVSS & Proactive Secret Sharing)** par aadharit hai.

Neeche har ek component ka detailed analysis aur SARAL POC ke sath status diya gaya hai:

| Component | Description | SARAL POC Status | Implementation Details |
|---|---|---|---|
| **Cryptographic Algorithms** | Secp256k1 (EVM/BTC), Ed25519 (Solana), NIST P-256 (AVSS baseline) | **Already Implemented** | `services/saral-node/cryptography/curves.go` & `services/saral-node/internal/crypto/curve_helpers.go` |
| **Pedersen Commitments** | $C_{j,l} = F_{j,l} \cdot G + F'_{j,l} \cdot H$ blinding commitments | **Already Implemented** | `services/saral-node/avss/commitments.go` |
| **Bivariate Polynomials** | Symmetrical 2D polynomials $F(x,y)$ degree $k-1$ | **Already Implemented** | `services/saral-node/avss/polynomial.go` |
| **HybridVSS Protocol** | Dual-threshold asynchronous VSS ($n=5, k=3, t=1$) | **Already Implemented** | `services/saral-node/avss/engine.go` & `participant.go` |
| **ECHO & READY Gossip** | Asynchronous Bracha-style reliable broadcast | **Already Implemented** | `services/saral-node/internal/relay/router.go` |
| **HybridDKG Agreement** | Leader-based consensus on Qualified Set (QUAL) | **Already Implemented & Integrated** | `services/saral-node/dkg/hybrid_dkg.go` |
| **Leader Change Mechanism** | Pessimistic view change when leader crashes | **Already Implemented & Integrated** | `services/saral-node/dkg/hybrid_dkg.go` |
| **P2P Node Relay Mesh** | Node-to-node direct TLS/HTTP messaging | **Adapted & Reused** | `services/saral-node/internal/relay/router.go` |
| **Coordinator & Verifier** | Centralized orchestration & verification services | **Incompatible / Removed** | Pure 2-component architecture mein eliminate kiya gaya |
| **Multi-Domain Derivation** | 3-Domain ($Y = Y_f + Y_p + Y_r$) address combination | **Already Implemented** | `apps/auth-server/src/utils/walletPublicKeys.ts` |
| **Zero-Persistence Rule** | Database mein ZERO private/public keys ya addresses | **Enforced** | `apps/auth-server/src/storage/store.ts` |

---

## 2. SARAL POC mein pehle se kya available tha

1. **Web2 Authentication System (`apps/auth-server`)**:
   - Google OAuth 2.0 aur Phone OTP verification.
   - RFC 6238 TOTP Multi-Factor Authentication (MFA) encrypted with AES-256-GCM.
   - Working Policy Engine (Time restriction, Geofencing, IP whitelisting).
   - PostgreSQL Prisma schema jisme sirf user metadata aur session references hain.

2. **Core Cryptographic Library (`services/saral-node/cryptography`)**:
   - Finite field arithmetic over prime orders.
   - Elliptic curve point addition, doubling, aur scalar multiplication.
   - Chaum-Pedersen DLEQ zero-knowledge proofs.
   - Bivariate polynomial matrix operations.

3. **15 Autonomous SARAL Nodes**:
   - 3 separate committees (5 Foundation, 5 Public, 5 Private nodes).
   - Har committee ka threshold $k=3$ out of $n=5$ with crash failure tolerance $t=1$.
   - Local encrypted disk storage (`/vault`) for secret shares.

---

## 3. Kaunsa Code Reuse kiya (Reused Implementations)

1. **`services/saral-node/dkg/hybrid_dkg.go`**:
   - Kate-Huang-Goldberg ACNS 2012 protocol ka leader-based agreement engine.
   - `LeaderProposalMessage`, `ProposalEchoMessage`, aur `ProposalReadyMessage` ka handling.
   - Pessimistic leader-change votes (`LeaderChangeMessage`) jab designated leader round time ke andar response na de.

2. **`services/saral-node/avss/`**:
   - `BivariatePolynomial`: Dealers ke liye 2D symmetric random polynomial generation.
   - `CommitmentMatrix`: Pedersen commitment matrix verification for rows and columns.
   - `ReconstructSecret`: Lagrange interpolation at $x=0$ on field elements.

3. **`services/saral-node/internal/relay/router.go`**:
   - Nodes ke beech point-to-point encrypted gossip delivery.
   - Nonce-based replay protection aur persistent deduplication cache.

---

## 4. Kaunsa Code Modify kiya (Architecture Refactor)

### A. Coordinator aur Verifier Nodes ka Pura Elimination
- **Old Flow:** `Auth Server -> Coordinator -> Verifier <-> Nodes`
- **New Flow:** `Auth Server -> SARAL Nodes (Direct)`
- `services/coordinator` aur `services/verifier` ko poori tarah delete kiya gaya.
- Jo essential operations Coordinator aur Verifier karte the, unhe **SARAL Node** ke andar directly implement kiya gaya:
  - **`services/saral-node/internal/rpc/jsonrpc.go`**: JSON-RPC handler add kiya jo Auth Server se direct requests leta hai:
    - `saral_startDkg`: DKG session shuru karta hai.
    - `saral_getDkgStatus`: Session progress aur quorum check karta hai.
    - `saral_derivePublicKey`: Commitments se public key shares derive karta hai.
    - `saral_getNodeStatus`: Gateway node ki health aur peer connectivity return karta hai.
  - **`services/saral-node/internal/crypto/curve_helpers.go`**:
    - Secp256k1 & Ed25519 point math.
    - Lagrange interpolation at $x=0$ in unblinded point space ($Y = \sum \lambda_i Y_i$).
    - Blockchain address formatters (Keccak-256 + EIP-55 for MST, Base58 for Solana, Bech32m for Bitcoin Taproot).

### B. Root Cause Fix: `WALLET_SERVICE_UNAVAILABLE`
- **Problem:** Docker Compose (`infra/compose/full24.yml`) mein SARAL nodes sirf mTLS port `8443` expose kar rahe the, jabki host par chal raha `apps/auth-server` port `8001` (Foundation), `8006` (Public), aur `8011` (Private) ko call kar raha tha. Port map na hone ki wajah se connection reject ho raha tha (`ECONNREFUSED`).
- **Solution:**
  - `infra/compose/full24.yml` aur `poc15.yml` mein sabhi 15 nodes ke liye host ports map kiye:
    - Foundation: `node-f1..f5` -> Ports `8001..8005`
    - Public: `node-p1..p5` -> Ports `8006..8010`
    - Private: `node-r1..r5` -> Ports `8011..8015`
  - Auth Server ab seedhe teeno domain gateways se connect hota hai aur DKG 100% successfully complete hota hai.

---

## 5. Har Important Function Kis File Mein Hai

| Function Name | File Path | Responsibility |
|---|---|---|
| `HandleJsonRpc` | `services/saral-node/internal/rpc/jsonrpc.go` | Auth Server se direct JSON-RPC calls dispatch karna |
| `DeriveMasterPublicKeyFromShares` | `services/saral-node/internal/crypto/curve_helpers.go` | Lagrange interpolation se public key derive karna |
| `DeriveEvmAddressFromPublicKey` | `services/saral-node/internal/crypto/curve_helpers.go` | Keccak-256 hash aur EIP-55 checksum MST address banana |
| `DeriveSolanaAddressFromPublicKey` | `services/saral-node/internal/crypto/curve_helpers.go` | 32-byte Ed25519 public key ko Base58 address mein convert karna |
| `DeriveBitcoinTaprootAddressFromPublicKey` | `services/saral-node/internal/crypto/curve_helpers.go` | BIP-341 Taproot tweak aur BIP-350 Bech32m address banana |
| `StartContribution` | `services/saral-node/dkg/engine.go` | Har node ka local secret aur polynomial create karna |
| `ComputeCommitmentMatrix` | `services/saral-node/avss/commitments.go` | 2D Pedersen commitment matrix $C_{j,l}$ compute karna |
| `StartOptimisticRound` | `services/saral-node/dkg/hybrid_dkg.go` | HybridDKG round 1 agreement proposal shuru karna |
| `CreateProposal` | `services/saral-node/dkg/hybrid_dkg.go` | Designated leader dwara certified QUAL set propose karna |
| `ProcessEcho` / `ProcessReady` | `services/saral-node/dkg/hybrid_dkg.go` | Reliable broadcast ke round-based votes process karna |
| `createOrGetWallet` | `apps/auth-server/src/services/walletService.ts` | Complete wallet creation pipeline orchestrate karna |
| `completeWalletDkg` | `apps/auth-server/src/services/walletService.ts` | 9 sessions ke DKG ko start aur monitor karna |
| `combineWalletPublicKeys` | `apps/auth-server/src/utils/walletPublicKeys.ts` | Teeno domains ($Y_f + Y_p + Y_r$) ke public points combine karna |

---

## 6. DKG Step-by-Step Execution Flow

1. **User Request:**
   User authenticated browser se `POST /api/wallet/generate` trigger karta hai.
2. **Policy Evaluation:**
   Auth Server user ka working policy (location, time) verify karta hai.
3. **Session Generation:**
   Auth Server 9 DKG session IDs generate karta hai (3 domains: foundation, public, private $\times$ 3 chains: mst, solana, bitcoin).
4. **RPC Start:**
   Auth Server teeno domain gateways (`localhost:8001`, `localhost:8006`, `localhost:8011`) ko `saral_startDkg` call karta hai Ed25519 auth token ke sath.
5. **Round 1 (Dealing Phase):**
   Har node apna random secret $z_i$ aur blinding factor $z'_i$ choose karta hai, 2D bivariate polynomial generate karta hai aur commitment matrix publish karta hai.
6. **Round 2 (AVSS Verification):**
   Nodes ek dusre ko polynomial slices bhejte hain. Recipient nodes commitment matrix ke against row/col polynomial verify karte hain.
7. **Round 3 (Agreement Phase - HybridDKG):**
   Leader certified completed nodes ka Qualified Set (`QUAL`) propose karta hai. Nodes ECHO aur READY messages exchange karte hain.
8. **Round 4 (Share Aggregation):**
   Agreement hone ke baad, har node QUAL ke sabhi dealers ke shares sum karke apna final share $s_i$ derive karta hai aur encrypted `/vault` mein store karta hai:
   $$x_j = \sum_{i \in \text{QUAL}} s_{i, j} \pmod N$$
   Complete private key kisi bhi ek server par kabhi bhi reconstruct nahi hoti.
9. **Status Confirmation:**
   Auth Server `saral_getDkgStatus` se verify karta hai ki kam se kam 3 nodes quorum achieve kar chuke hain.

---

## 7. Wallet Address Kaise Generate Hota Hai

SARAL Protocol **Strict Zero-Persistence** rule follow karta hai:
Database mein koi bhi Private Key, Public Key ya Wallet Address save nahi hota.

Address derivation memory mein real-time hota hai:

### Step 1: Public Key Shares Fetching
Auth Server nodes se public key shares mangta hai (`saral_derivePublicKey`):
$$Y_{\text{domain}} = \sum_{i \in \text{QUAL}} \lambda_i V_i$$
Jahan $V_i = z_i \cdot G$ unblinded public commitments hain aur $\lambda_i$ Lagrange coefficients at $x=0$ hain.

### Step 2: 3-Domain Point Combination
Teeno domains ke public points elliptic curve addition ke zariye combine hote hain:
$$Y_{\text{master}} = Y_{\text{foundation}} + Y_{\text{public}} + Y_{\text{private}}$$

### Step 3: Blockchain-Specific Formatting
- **MST Testnet (secp256k1 EVM):**
  1. $Y_{\text{master}}$ (64-byte uncompressed point without `04` prefix) ka Keccak-256 hash liya jata hai.
  2. Last 20 bytes extract kiye jate hain.
  3. EIP-55 mixed-case checksum lagaya jata hai $\to$ `0x...`
- **Solana Devnet (ed25519):**
  1. Compressed 32-byte Ed25519 public key point liya jata hai.
  2. Bitcoin/Solana standard Base58 encoding apply ki jaati hai $\to$ `Base58 String`
- **Bitcoin Testnet (secp256k1 Taproot):**
  1. BIP-340 standard 32-byte X-only public coordinate extract kiya jata hai.
  2. BIP-341 Taproot output tweak apply hota hai ($Q = P + \text{hash}_{\text{TapTweak}}(P) \cdot G$).
  3. BIP-350 Bech32m encoding apply hoti hai with hrp `tb` and witness version `1` $\to$ `tb1p...`

---

## 8. Project Ko Kaise Run Aur Test Karna Hai

### A. Prerequisites Check
PostgreSQL running hona chahiye aur Docker installed hona chahiye.

### B. SARAL 15-Node Docker Cluster Start Karna
```bash
# 15 SARAL Nodes aur PostgreSQL start karein
node scripts/docker-stack.cjs nodes
```

Status check karein:
```bash
curl -s http://localhost:8001/node/status  # Foundation Node 1
curl -s http://localhost:8006/node/status  # Public Node 1
curl -s http://localhost:8011/node/status  # Private Node 1
```

### C. Host Par Auth Server aur Web UI Run Karna
```bash
npm run dev
```
- Auth Server: `http://localhost:3001`
- Frontend UI: `http://localhost:5173`

### D. Automated Test Suites Run Karna
```bash
# 1. TypeScript & Architecture Integration Tests (44 Vitest tests)
npm run test:ts

# 2. Go SARAL Node Unit & Cryptography Tests
cd services/saral-node && go test -v ./...

# 3. Complete End-to-End Cryptography Suite
npm run test:all-crypto
```

### E. Production Build Verification
```bash
npm run build
```
Yeh command Go binary, Prisma client, Auth Server TypeScript bundle, aur Vite frontend web package compile karti hai.
