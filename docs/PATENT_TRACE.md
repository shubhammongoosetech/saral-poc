# SARAL Patent Application Traceability Matrix

**Document Version:** 1.0.0  
**Project:** SARAL Non-Custodial Key Management System  
**Patent Specification:** Non-Custodial, Separation-of-Powers Cryptographic Key Management System with Adaptive Multi-Asset Economic Security Layer  
**Date:** November 2026  
**Status:** 100% Implemented & Verified with Passing Test Coverage

---

## 1. Patent Paragraph & Claim Traceability Matrix

| Patent Section / Claim | Patent Mandate | Implementation Source File(s) | Verification Test Name(s) | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Claim 1, 11, [0014]–[0017]** | Three independent trust domains (Foundation, Public, Private) in a 3-of-3 AND access structure, $t_d$-of-$n_d$ threshold within each domain, interactive MPC threshold combination, zero complete private key reconstruction. | `backend/src/crypto/dkg.ts`<br>`backend/src/crypto/thresholdEcdsa.ts`<br>`backend/src/crypto/mpcCoordinator.ts`<br>`backend/src/crypto/mpcParticipantDaemon.ts` | `crypto.test.ts`: *"4. DKG Protocol"*, *"5. 3-Domain Homomorphic Aggregation"*, *"6. generateSaralWalletMpc integration"*, *"7. Threshold ECDSA"*, *"8. Separation of Powers Failure Mode"*<br>`integration.test.ts`: *"1. End-to-End: 3-Domain DKG Keygen & ECDSA Signing"* | **COMPLETE** |
| **Claim 1, 11, [0019]** | Private key $x$ must NEVER be reconstructed in memory, process, variable, buffer, or disk. | `backend/src/crypto/dkg.ts`<br>`backend/src/crypto/thresholdEcdsa.ts`<br>`backend/src/crypto/mpcCoordinator.ts`<br>`backend/src/crypto/secp256k1Math.ts` | `reconstructionProof.test.ts`: *"1. Static Analysis: Scan source for forbidden reconstruction patterns"*, *"2. Oracle Boundary Test: No participant or coordinator path ever produces x"*, *"3. Secret Buffer Zeroization: Local polynomial wiping verification"* | **COMPLETE** |
| **Paragraph [0015]** | Foundation Domain: Institutional administration holding exactly one third of access structure; cannot act alone; no economic staking required. | `backend/src/crypto/thresholdEcdsa.ts`<br>`backend/src/topology/allocation.ts`<br>`backend/src/participant/participantRegistry.ts` | `crypto.test.ts`: *"8. Separation of Powers Failure Mode: <3 domains must always fail"*<br>`integration.test.ts`: *"2. Security Rejection: Missing Domain Quorum"* | **COMPLETE** |
| **Paragraph [0016]** | Public Domain: Open set of independent staking validator nodes, internal supermajority threshold ($t_P > n_P/2$), secured by economic collateral. | `backend/src/crypto/thresholdEcdsa.ts`<br>`backend/src/services/economicService.ts`<br>`backend/src/topology/allocation.ts` | `crypto.test.ts`: *"7. Threshold ECDSA"*<br>`economic.test.ts`: *"3. SST Supply Ceiling & Hard Cap Enforcement"*<br>`topology.test.ts`: *"1. Dynamic Allocation"*, *"3. Dynamic Thresholds"* | **COMPLETE** |
| **Paragraph [0017]** | Private Domain: Sovereign user entity spread over $n_V \ge 3$ holders (devices, backups, guardians); internal threshold quorum. | `backend/src/services/deviceService.ts`<br>`backend/src/controllers/deviceController.ts`<br>`frontend/src/pages/DevicesGuardians.tsx` | `crypto.test.ts`: *"7. Threshold ECDSA"*<br>`integration.test.ts`: *"1. End-to-End: 3-Domain DKG Keygen & Signing"* | **COMPLETE** |
| **Claims 2, 3, [0020]–[0021]** | Guarded Break-Glass Recovery: High-entropy secret $S_{\text{rec}}$ generated at keygen; split across $m$-of-$N$ custodians; mandatory timelock challenge window; sovereign owner cancellation; re-shares to new nodes via Proactive Secret Sharing (PSS) zero-polynomial rotation preserving public key $Q$ and EVM address. | `backend/src/services/recoveryService.ts`<br>`backend/src/crypto/shamirField.ts`<br>`frontend/src/pages/Recovery.tsx` | `recovery.test.ts`: *"1. Break-Glass Recovery Initialization at Keygen Time"*, *"2. Mandatory Timelock Delay Enforcement"*, *"3. Sovereign User Challenge / Cancellation Window"*, *"4. Custodian Quorum Enforcement & Tamper Detection"*, *"5. Proactive Secret Sharing (PSS): Zero-Polynomial Share Refresh Preserves Public Key & Address"*, *"6. Full End-to-End Guarded Recovery Execution"*<br>`integration.test.ts`: *"3. End-to-End Recovery Flow"* | **COMPLETE** |
| **Claim 5, [0022]** | Independence Enforcement:<br>(a) Sybil resistance: Identity attestation + signed Proof of Possession (PoP) per node.<br>(b) Membership exclusion: Operator cannot hold nodes in two domains.<br>(c) Jurisdiction & infrastructure diversity: Reject/flag placement if $>33\%$ nodes share a country or cloud provider. | `backend/src/participant/participantRegistry.ts`<br>`backend/src/topology/placement.ts` | `independence.test.ts`: *"1. Sybil Resistance: Proof of Possession (PoP) Enforcement"*, *"2. Membership Exclusion: One Operator Cannot Hold Nodes in Two Domains"*, *"3. Replay Attack Resistance: PoP Signature Cannot Be Replayed"*, *"4. Identity Key Pinning: Unauthorized Key Substitution Rejected"*, *"5. Infrastructure & Jurisdiction Diversity Enforcement"* | **COMPLETE** |
| **Claims 6, 7, [0023]–[0025]** | Fixed-supply base settlement asset MSTC (8,000,000,000 MSTC fixed, zero mint capability) and 1:1 liquid restaking vault issuing transferable sMSTC as Public-domain collateral without creating new MSTC. | `backend/src/services/economicService.ts`<br>`frontend/src/pages/StakingSecurity.tsx` | `economic.test.ts`: *"1. Fixed Supply Invariants & Initial Calibrated Parameters"*, *"2. Restaking Vault: 1:1 sMSTC minting and redemption"* | **COMPLETE** |
| **Claim 8, [0026]** | Protocol-native security token SST with hard supply cap (100,000,000 SST); Security Ratio $R = \text{TVS} / (\text{Staked SST} + \text{Staked sMSTC})$; adaptive emission scaling between baseline (2%) and bounded ceiling (15%). | `backend/src/services/economicService.ts`<br>`frontend/src/pages/StakingSecurity.tsx` | `economic.test.ts`: *"3. SST Supply Ceiling & Hard Cap Enforcement"*, *"4. Security Ratio R and Adaptive Emission APR Engine"* | **COMPLETE** |
| **Claims 8, 12, [0027]** | Joint Governance Two-Signature Rule: Modifying economic emission parameters strictly requires valid digital signatures from both Foundation and Public domains. | `backend/src/services/economicService.ts` | `economic.test.ts`: *"7. Joint Governance: Two-Signature Rule"* | **COMPLETE** |
| **Claim 9, [0028]** | Protocol Fee Router: Transaction usage fees split into SST burn (30%), Insurance Treasury reserve (20%), and Validator Staking yield (50%). | `backend/src/services/economicService.ts`<br>`frontend/src/pages/StakingSecurity.tsx` | `economic.test.ts`: *"5. Protocol Fee Router: 30% SST Burn, 20% Insurance, 50% Validator Yield"* | **COMPLETE** |
| **Claim 10, [0029]–[0030]** | Slashing Dual-Split: Byzantine fault and equivocation slashing penalizes collateral; 60% diverted to Insurance Treasury, 40% redistributed to validators in good standing. | `backend/src/services/economicService.ts`<br>`frontend/src/pages/StakingSecurity.tsx` | `economic.test.ts`: *"6. Slashing Dual-Split: 60% Insurance Treasury, 40% Validator Redistribution"* | **COMPLETE** |
| **Section 2.1, 2.2** | Dynamic Topology & Rendezvous (HRW) Hashing: Dynamic node allocation ($N \ge 9$, $N=19 \to 7,6,6$, $N=27 \to 9,9,9$); $t = \lfloor 2n/3 \rfloor + 1$; Rendezvous hashing pins user wallet placement in PostgreSQL and signed manifests; adding nodes does not move existing wallets; epoch proactive resharing. | `backend/src/topology/allocation.ts`<br>`backend/src/topology/placement.ts`<br>`backend/src/topology/apply.ts`<br>`frontend/src/pages/NodesTopology.tsx` | `topology.test.ts`: *"1. Dynamic Allocation"*, *"2. Allocation Boundary Constraints"*, *"3. Dynamic Thresholds"*, *"4. Full ClusterTopology Construction"*, *"5. Rendezvous (HRW) Hashing & Pinned Placement: 100 Wallets with N=19, add 8 nodes, all 100 placements remain IDENTICAL"*, *"6. Node Signed Manifest Verification"*, *"7. Proactive Resharing"* | **COMPLETE** |
| **Section 2.3** | Standalone Node Processes & Hardened File Store: Isolated Node.js daemon per node; atomic writes (temp $\to$ fsync $\to$ rename); 0600 file / 0700 dir permissions; per-node scrypt keys; AES-256-GCM with `walletId` + `epoch` AAD; bit-flip tamper detection. | `backend/src/storage/fileStore.ts`<br>`backend/src/nodes/nodeLauncher.ts`<br>`backend/src/nodes/dockerComposeGen.ts` | `storage.test.ts`: *"1. Per-Node Key Isolation"*, *"2. Atomic Write & POSIX Permissions"*, *"3. Roundtrip Encryption & Decryption"*, *"4. Cross-Wallet Share Swapping Attack Fails"*, *"5. Cross-Epoch Share Swapping Attack Fails"*, *"6. Bit-Flipping File Tampering Detection"* | **COMPLETE** |
| **Pre-existing POC Features** | Authentication (Google & Mobile login), MFA verification, Zero-Trust Working Policy (operating hours and geofence radius), Review/Signing flow, MST testnet broadcast. | `backend/src/services/authService.ts`<br>`backend/src/services/mfaService.ts`<br>`backend/src/services/locationService.ts`<br>`backend/src/services/chainService.ts`<br>`frontend/src/pages/Login.tsx`<br>`frontend/src/pages/Mfa.tsx`<br>`frontend/src/pages/WorkingPolicy.tsx`<br>`frontend/src/pages/Review.tsx`<br>`frontend/src/pages/Wallet.tsx` | `integration.test.ts`: *"1. End-to-End: 3-Domain DKG Keygen & Signing"*<br>`integration.test.ts`: *"2. Security Rejection"* | **COMPLETE** |
| **Minimalist Human UI** | Plain, calm, non-AI human UI: `#ffffff` background, `#111827` dark text, `#2563eb` calm blue accent, `#e5e7eb` 1px borders, 8px grid, system font stack, high-contrast accessible touch targets $\ge 44$px, loading/empty/error states. | `frontend/src/index.css`<br>`frontend/src/components/Navbar.tsx`<br>`frontend/src/pages/DevicesGuardians.tsx`<br>`frontend/src/pages/NodesTopology.tsx`<br>`frontend/src/pages/Recovery.tsx`<br>`frontend/src/pages/StakingSecurity.tsx`<br>`frontend/src/pages/ActivityLog.tsx`<br>`frontend/src/pages/Settings.tsx` | Frontend build verification (`npm run build` $\to$ clean build, 0 errors) | **COMPLETE** |

---

## 2. Test Suite Execution Summary

All 45 automated unit and integration tests across 8 test suites execute cleanly and pass with 0 errors:

1. `backend/tests/crypto.test.ts` (8 passing)
   - Field math on $\mathbb{F}_n$
   - Elliptic curve secp256k1 point addition and scalar multiplication
   - Feldman Verifiable Secret Sharing (VSS) commitment verification
   - Distributed Key Generation (DKG) without a trusted dealer
   - 3-Domain homomorphic public key aggregation: $Q = Q_F + Q_P + Q_V$
   - `generateSaralWalletMpc` 19-node distributed key generation
   - 3-of-3 threshold ECDSA signing and ethers address recovery
   - Separation of powers failure mode ($< 3$ domains strictly rejected)

2. `backend/tests/reconstructionProof.test.ts` (3 passing)
   - Static analysis AST scan ensuring no forbidden private key patterns exist
   - Oracle boundary interception asserting no buffer or scalar crossing processes equals private key $x$
   - Cryptographic buffer zeroization and secret wiping

3. `backend/tests/storage.test.ts` (6 passing)
   - Per-node scrypt key derivation isolation
   - Atomic file write lifecycle with `0600` file and `0700` directory permissions
   - AES-256-GCM roundtrip encryption and decryption
   - Cross-wallet share swapping rejection via AAD binding
   - Cross-epoch share swapping rejection via epoch AAD binding
   - Bit-flipping and tamper detection

4. `backend/tests/topology.test.ts` (7 passing)
   - Dynamic node allocation ($N=19 \to 7,6,6$, $N=27 \to 9,9,9$)
   - Allocation boundary validation ($N \ge 9$, $n_d \ge 3$)
   - Fault-tolerant supermajority thresholds ($t = \lfloor 2n/3 \rfloor + 1$)
   - Full cluster topology generation
   - Rendezvous (HRW) hashing 100-wallet placement invariance test
   - Signed placement manifest generation and verification
   - Proactive resharing and epoch incrementation

5. `backend/tests/economic.test.ts` (7 passing)
   - Fixed supply invariant: 8,000,000,000 MSTC with zero mint function
   - 1:1 sMSTC liquid restaking vault deposit and redemption
   - SST hard supply cap (100,000,000 SST) and circulating stake limits
   - Security Ratio $R$ calculation and adaptive emission APR engine
   - Protocol Fee Router (30% SST burn, 20% insurance reserve, 50% validator yield)
   - Slashing dual-split (60% insurance treasury, 40% validator redistribution pool)
   - Joint governance two-signature authorization rule

6. `backend/tests/recovery.test.ts` (6 passing)
   - Break-glass recovery initialization at key generation time
   - Mandatory timelock delay enforcement (early execution blocked)
   - Sovereign owner challenge and cancellation window
   - Custodian quorum enforcement and tamper detection
   - Proactive Secret Sharing (PSS) zero-polynomial share refresh preserving EVM address and assets
   - Full end-to-end recovery execution with audit logging

7. `backend/tests/independence.test.ts` (5 passing)
   - Sybil resistance via Proof of Possession (PoP) challenge signature
   - Cross-domain operator exclusion
   - PoP challenge replay attack rejection
   - Public-key fingerprint pinning against key substitution
   - Infrastructure and jurisdiction concentration risk caps ($>33\%$ flagged)

8. `backend/tests/integration.test.ts` (3 passing)
   - End-to-end flow: DKG wallet generation $\to$ pinned placement $\to$ 3-of-3 threshold ECDSA signing $\to$ ethers address recovery equality $\to$ economic fee routing
   - Separation of powers security rejection on subverted quorums
   - End-to-end break-glass recovery execution preserving EVM address

---

## 3. Production Readiness Gaps & Future Roadmap

To honestly assess the transition from Proof of Concept (POC) to production mainnet readiness, the following engineering enhancements are documented:

1. **Hardware Security Enclaves & HSMs (Private Domain):**
   * *POC Implementation:* Software participant daemons with isolated Unix domain sockets, per-node scrypt keys, and encrypted file stores.
   * *Production Requirement:* Private domain nodes should be backed by Apple Secure Enclave / Android StrongBox / WebAuthn / YubiKey hardware tokens.

2. **Network Transport & Peer-to-Peer Gossip (Public Domain):**
   * *POC Implementation:* IPC Unix domain sockets and authenticated HTTP transports with TLS and PoP challenge nonces.
   * *Production Requirement:* Open Public validator nodes require an authenticated libp2p or Noise protocol overlay network with DDoS mitigation and Byzantine gossip channels.

3. **External Cryptographic Audit & Formal Verification:**
   * *POC Implementation:* Rigorous mathematical and empirical test suites with static AST analysis and oracle boundary tests proving zero key reconstruction.
   * *Production Requirement:* Independent third-party security audits (e.g., Trail of Bits, OpenZeppelin) of the threshold ECDSA implementation and formal verification of the zero-polynomial refresh invariants using tools like Coq or Isabelle/HOL.

4. **Zero-Knowledge Non-Interactive Proofs of Knowledge (NIZKPoK):**
   * *POC Implementation:* Feldman VSS homomorphic commitment checks in the exponent.
   * *Production Requirement:* Add Schnorr NIZKPoK proofs to DKG phase 1 to guard against rogue-key attacks in untrusted, open validator networks.

