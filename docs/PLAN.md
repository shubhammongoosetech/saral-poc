# Implementation Plan: SARAL POC Rebuild

**Document Version:** 1.0.0  
**Project:** SARAL Non-Custodial Key Management System  
**Standard:** SARAL Patent Application Specification  
**Date:** November 2026

---

## Overview

This document specifies the step-by-step implementation phases for rebuilding `saral-poc` strictly according to the SARAL patent specification. Every patent claim maps to concrete code, hardened architecture, and passing tests.

---

## Phase Breakdown

### Phase 1: Hygiene, Dependencies & Clean Slate
* **Objective:** Clean untracked artifacts, fix dependency manifests, configure TypeScript, and create database migrations.
* **Actions:**
  1. Wipe scratch runtime directories: `.saral_node_keys/`, `.saral_node_vault/`, `.saral_registry/`, `.saral_runtime_sockets/`, `.saral_test_19node_vault/`, `.saral_p523_test_vault_*/`, `backend/dist/`, `frontend/dist/`.
  2. Install required dependencies: `cookie-parser`, `@types/cookie-parser` in `backend/package.json`.
  3. Fix `frontend/tsconfig.json` by adding `"types": ["vite/client"]` to resolve Vite environment and asset typing.
  4. Fix compilation references in `backend/src/crypto/secureEncryption.ts` and `backend/src/services/mfaService.ts` to remove stale `env.MASTER_ENCRYPTION_KEY` dependencies.
  5. Add database migration `backend/src/db/migrations/004_add_wallet_placements.sql` for the `wallet_placements` table, and update `backend/prisma/schema.prisma` and `backend/src/db/schema.sql`.

### Phase 2: Core Cryptographic & DKG Engine (No Single Dealer)
* **Objective:** Eliminate single-point key materialization and implement true Distributed Key Generation (DKG) across the 3 domains.
* **Files to create/modify:**
  * `backend/src/crypto/dkg.ts`: Complete Feldman VSS DKG ceremony (joint polynomial sampling, verifiable commitments, sub-share distribution, share accumulation, and elliptic curve public point addition).
  * `backend/src/crypto/thresholdEcdsa.ts`: Refactor to execute DKG without central scalar sampling, and maintain 3-of-3 cross-domain threshold ECDSA signing.
  * `backend/src/crypto/shamirField.ts`: Harden Lagrange and zero-polynomial utilities for proactive resharing.
* **Tests to create:**
  * `backend/tests/crypto.test.ts`: Verify field math, Feldman commitments, DKG without a dealer, and point addition $Q = Q_F + Q_P + Q_V$.
  * `backend/tests/reconstructionProof.test.ts`: AST scan for forbidden patterns (`Wallet.createRandom`, `new Wallet(privateKey`, scalar combining) and oracle process assertion that no buffer equal to the private key crosses any boundary.

### Phase 3: Dynamic Topology, Standalone Nodes & Hardened File Store
* **Objective:** Replace static 19-node assumptions with dynamic containers ($N \ge 9$), Rendezvous (HRW) hash placement, and hardened per-node encrypted storage.
* **Files to create/modify:**
  * `backend/config/topology.json`: Topology specification (nodes, ports, domains, weights).
  * `backend/src/topology/allocation.ts`: Dynamic allocation function `allocate(N, weights)` and threshold calculation $t = \lfloor 2n/3 \rfloor + 1$.
  * `backend/src/topology/placement.ts`: Rendezvous (HRW) hashing algorithm and database pinning in `wallet_placements`.
  * `backend/src/storage/fileStore.ts`: File storage implementation enforcing atomic writes (temp file $\to$ `fsync` $\to$ `rename`), file mode `0600`, directory mode `0700`, per-node `scrypt` key derivation, and AES-256-GCM with `walletId` + `epoch` AAD.
  * `backend/src/nodes/nodeLauncher.ts`: CLI runner supporting `npm run nodes:start -- --foundation 7 --public 6 --private 6`.
  * `backend/src/nodes/dockerComposeGen.ts`: Dynamic Docker Compose generator reflecting the active topology.
* **Tests to create:**
  * `backend/tests/topology.test.ts`: Verify allocation for $N=19$ and $N=27$, HRW consistency (100 wallets generated with $N=19$, 8 nodes added, assert placements are 100% identical), and epoch resharing.
  * `backend/tests/storage.test.ts`: Test atomic writes, per-node key derivation, AAD tamper detection, and file integrity validation.

### Phase 4: Independence Enforcement, Recovery & Economic Security
* **Objective:** Implement Sybil resistance, cross-domain exclusion, break-glass recovery with time-locks, and the adaptive multi-asset economic security layer.
* **Files to create/modify:**
  * `backend/src/participant/participantRegistry.ts`: Enforce Sybil stake deposits, identity attestation, cross-domain operator exclusion, and infrastructure diversity concentration limits.
  * `backend/src/services/recoveryService.ts`: Break-glass recovery lifecycle with mandatory time-lock challenge window, cancellation window, and PSS zero-polynomial share rotation preserving wallet address.
  * `backend/src/services/economicService.ts`: 8B fixed MSTC, 1:1 sMSTC liquid restaking vault, SST hard cap, security ratio $R$, dynamic APR emission, fee burn-and-mint router, and 60/40 slashing split.
* **Tests to create:**
  * `backend/tests/economic.test.ts`: Test 1:1 restake, SST ceiling, security ratio calculation, adaptive emission, fee split, and 60/40 slashing allocation.
  * `backend/tests/recovery.test.ts`: Test break-glass generation, time-lock challenge, cancellation, and PSS share refresh.
  * `backend/tests/independence.test.ts`: Test Sybil resistance rejection, cross-domain operator exclusion, and cloud provider diversity caps.

### Phase 5: Backend Controllers, Routes & Integration
* **Objective:** Connect all modules to the Express API with hardened authentication, CSRF, rate-limiting, and fresh MFA gating.
* **Files to create/modify:**
  * `backend/src/services/walletService.ts`: Integrate DKG, HRW placement pinning, and node file store into wallet generation and signing.
  * `backend/src/controllers/walletController.ts`: Add endpoints for dynamic topology, private devices/guardians, economic metrics, and recovery.
  * `backend/src/routes/wallet.ts`: Update routes with strict rate-limiting and fresh MFA validation.
  * `backend/src/routes/topology.ts`, `backend/src/routes/economic.ts`, `backend/src/routes/guardians.ts`: New dedicated route modules.
* **Tests to create:**
  * `backend/tests/integration.test.ts`: End-to-end integration test (User Signup $\to$ MFA $\to$ Working Policy $\to$ DKG Wallet Generation $\to$ Pinned Placement $\to$ Threshold MPC Sign $\to$ Recovered Address Match $\to$ MST Testnet Broadcast).
  * Negative security tests: missing domain fails, $< t$ nodes fails, tampered share fails, replayed request fails, out of policy fails, stale MFA fails.

### Phase 6: Frontend - All 11 Screens & Minimalist Human Design
* **Objective:** Build all missing frontend views conforming strictly to the minimalist, human-designed aesthetic.
* **Files to modify/create:**
  * Existing enhanced views: `Login.tsx`, `Mfa.tsx`, `WorkingPolicy.tsx`, `Review.tsx`, `Wallet.tsx`.
  * New views:
    * `frontend/src/pages/DevicesGuardians.tsx`: Manage Private domain devices and guardians.
    * `frontend/src/pages/NodesTopology.tsx`: View 3 containers, node counts, thresholds, node health, pinned placement, and epoch.
    * `frontend/src/pages/Recovery.tsx`: Initiate break-glass recovery, live time-lock countdown timer, approvals, and cancellation.
    * `frontend/src/pages/StakingSecurity.tsx`: View Security Ratio $R$, staked assets, emission APR, fee burning, and slashing events.
    * `frontend/src/pages/ActivityLog.tsx`: Tamper-evident access log history with geolocation coordinates and reasons.
    * `frontend/src/pages/Settings.tsx`: User profile, active sessions, and logout everywhere.
  * Navigation: `frontend/src/components/Navbar.tsx` and `frontend/src/App.tsx`.
  * Styling: Pure white background, near-black text, calm blue accent, 8px grid, responsive down to 360px, accessible.

### Phase 7: Patent Traceability & Final Verification
* **Objective:** Run all test suites, typechecks, and linter across the entire stack, and produce `docs/PATENT_TRACE.md`.
* **Deliverables:**
  * `docs/PATENT_TRACE.md`: Comprehensive table mapping patent paragraph / claim $\to$ source file $\to$ test name $\to$ status.
  * Green build: `npm test`, `npm run typecheck`.

