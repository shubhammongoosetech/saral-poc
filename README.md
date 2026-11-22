# SARAL Protocol

SARAL is a proof of concept for account-based, multi-chain testnet wallets backed by distributed key generation (DKG) and Threshold Signature Scheme (TSS). It supports wallet setup, receive addresses, balances, activity, and threshold transaction signing for MST Testnet, Solana Devnet, and Bitcoin Testnet.

Read the [SARAL code roadmap](docs/SARAL-Code-Roadmap.pdf) for the UI-to-node flow, a guided source reading order, and the signing references. The [architecture notes](SARAL_ARCHITECTURE.md) give more protocol background.

## Architecture

```text
React web app -> Express auth API -> PostgreSQL wallet and session metadata
                       |
                       +-> Foundation coordinator -> 5 Foundation nodes
                       +-> Public coordinator     -> 5 Public nodes
                       +-> Private coordinator    -> 5 Private nodes
```

Each domain has its own verifier. Each node persists its own encrypted DKG shares. The application database stores one wallet row per account, with opaque key and session references. The auth server derives addresses on demand from verified public keys.

| Start here | Follow the code |
| --- | --- |
| Browser routes and session | [Router](apps/web/src/app/router.tsx), [session provider](apps/web/src/features/auth/useSession.tsx) |
| Google, OTP, and MFA | [Auth routes](apps/auth-server/src/routes/auth.ts), [Google verification](apps/auth-server/src/auth/google.ts), [MFA service](apps/auth-server/src/services/mfaService.ts) |
| Wallet page and network calls | [Wallet](apps/web/src/features/wallet/Wallet.tsx), [wallet API](apps/web/src/services/walletApi.ts) |
| API, policy, and wallet persistence | [Wallet routes](apps/auth-server/src/routes/wallet.ts), [policy service](apps/auth-server/src/services/policyService.ts), [wallet service](apps/auth-server/src/services/walletService.ts), [store](apps/auth-server/src/storage/store.ts) |
| Three-domain RPC, DKG, and node storage | [Coordinator client](apps/auth-server/src/clients/saralBackendClient.ts), [coordinator DKG](services/coordinator/internal/rpc/dkg.go), [node DKG engine](services/saral-node/dkg/engine.go), [encrypted share store](services/saral-node/vault/share_store.go) |

## Run locally on Windows

Use PowerShell at the repository root with Node.js 22, npm 10+, and Docker Desktop with Compose v2. Go 1.23+ is needed for host Go tests. Stop any local service using the stack's published ports before starting it.

The Compose files expect a provisioned local mesh. Keep the auth Ed25519 key pair and matching public-key mount under `infra/config`, the node TLS material under `infra/tls`, and a genesis manifest whose signing and encryption public keys match the 15 node identities. Keep the private material local. `npm.cmd run setup` starts the same data-preserving path as `docker:nodes`.

### Run the web app and auth API on the host

```powershell
npm.cmd ci
npm.cmd run docker:nodes
npm.cmd run prisma:generate

$env:NODE_ENV = 'development'
$env:DATABASE_URL = '<local PostgreSQL URL>'
$env:GOOGLE_CLIENT_ID = '<your Google OAuth web client ID>'
npm.cmd run dev
```

Set `DATABASE_URL` to the local Compose database connection from the [app environment template](apps/auth-server/.env.example). Pass configuration to the host process through PowerShell environment variables. The public client ID comes from auth-server `GOOGLE_CLIENT_ID`. Use a Google OAuth web client that allows the frontend origin you open, `http://localhost:5173` for Vite.

To use local development phone login, set `$env:ENABLE_DEV_AUTH = 'true'` before `npm.cmd run dev`. The Vite development UI then offers phone OTP and development MFA codes. The code is entered manually. Normal sign-in uses Google and an authenticator code.

The [Docker startup script](scripts/docker-stack.cjs) waits for PostgreSQL, applies the additive Working Policy migration to fresh or existing local volumes, then starts the domain services. The web app uses [localhost:5173](http://localhost:5173) and the auth health endpoint is [localhost:3001/health](http://localhost:3001/health).

### Run the full Docker stack

```powershell
$env:GOOGLE_CLIENT_ID = '<your Google OAuth web client ID>'
npm.cmd run docker:full
npm.cmd run docker:status
```

Open [localhost:3000](http://localhost:3000) after the services are healthy. Configure Google for that browser origin when using the full Docker stack. Nginx proxies `/api` to the auth server. The full-stack web image uses a production frontend build, so local phone OTP is available through the preceding host workflow. `npm.cmd run docker:down` stops the containers and keeps the named volumes.

## Use the wallet

1. Sign in with Google or opt-in local phone OTP. New users enroll an authenticator and save their recovery codes. Existing users verify with their authenticator or a recovery code.
2. On first setup, save and confirm a Working Policy. Wallet requests enforce the configured schedule and, if enabled, the geofence.
3. Open **Wallet** and select **Create Wallet**. The server reserves the account's wallet ID and starts one DKG per chain in each of the three domains. A progress or retry screen uses that same reservation.
4. Once setup completes, use **Receive / QR** for the address you need. The wallet displays testnet balances and activity.
5. Sign out and sign in again with the same account. After MFA, the app opens `/wallet` and loads the same receive addresses. In the browser's Network panel, compare `wallet.walletId` in the two `GET /api/wallet` responses. With a valid session, refreshing the page also loads the existing wallet.

| Wallet state | What the app shows |
| --- | --- |
| No wallet row | Create Wallet |
| DKG in progress or interrupted | Check Status or Resume Wallet Setup |
| Setup error | Retry Wallet Setup using the saved reservation |
| Ready | Addresses, receive QR, balances, and activity |
| Access or derivation failure | An error with a reload action |
| Legacy P-256 shared session | Recovery required. The saved row is retained |

Wallets already created with three native per-chain sessions in the Foundation domain continue to use those sessions and keep their addresses. Older wallets that contain a single shared P-256 session require recovery.

### Chains and quorum

| Chain | Key curve | Receive address |
| --- | --- | --- |
| MST Testnet | secp256k1 | EVM address with EIP-55 checksum |
| Solana Devnet | Ed25519 | Base58-encoded Ed25519 public key |
| Bitcoin Testnet | secp256k1 | Taproot witness v1 Bech32m address |

A new wallet has nine DKG sessions. For each chain, derivation needs a 3-of-5 quorum in each of Foundation, Public, and Private, with a configured fault parameter of `t=1` per domain. The three verified domain public keys for that chain are added in the chain's group, then encoded as one receive address. MST and Bitcoin use separate keys.

### Main API paths

| Method and path | What it does |
| --- | --- |
| `GET /api/auth/login-options` | Returns the configured public Google client ID and development OTP availability |
| `POST /api/auth/google` | Verifies the Google credential and creates a first-factor session |
| `POST /api/auth/otp/request`, `POST /api/auth/otp/verify` | Local development phone sign-in |
| `GET /api/mfa/status`, `POST /api/mfa/enroll`, `POST /api/mfa/verify` | Checks enrollment, sets up the authenticator, and upgrades the session after verification |
| `GET /api/profile`, `POST /api/profile/policy` | Loads the account and saves the Working Policy |
| `POST /api/wallet/check-access` | Evaluates the current time and optional location policy |
| `POST /api/wallet/generate` | Creates, resumes, or returns the authenticated user's wallet |
| `GET /api/wallet`, `GET /api/wallet/transactions` | Reads the wallet and live activity |
| `POST /api/wallet/sign` | Executes 15-node distributed Threshold Signature Scheme (TSS) transaction signing across 3 domains without private key reconstruction |

## Verify

```powershell
npm.cmd run typecheck
npm.cmd --prefix apps/web test
npm.cmd run test:ts
npm.cmd run test:go
npm.cmd run test:all-crypto
```

The browser tests cover session and wallet transitions. The architecture tests exercise wallet lifecycle, cryptographic scope, and persistence. Run Docker checks against the running stack when verifying coordinator connectivity and actual testnet calls.

Verification on `saral-mohit-new` includes:
- **Zero-Persistence Guarantee:** Verified that PostgreSQL contains zero private keys, zero public keys, and zero addresses.
- **DKG & AVSS:** 15 distributed nodes across 3 sovereign domains (Foundation, Public, Private) with $k=3$ threshold.
- **Returning User Determinism:** Evaluates public polynomial points at $x=0$, deriving identical MST, Solana, and Bitcoin addresses upon login without re-running DKG.
- **TSS Multi-Chain Signing:** Implemented threshold signing without key reconstruction:
  - **MST Testnet:** secp256k1 ECDSA with BIP-62/EIP-2 low-S normalization.
  - **Solana Devnet:** Ed25519 FROST threshold signing with Base58 transaction hash.
  - **Bitcoin Testnet:** BIP-340 Schnorr / BIP-341 Taproot threshold signing.
- **Developer OTP Mode:** One-click auto-fill on OTP input screen for rapid local testing.

## Signing References & Architecture

- **Solana** uses Ed25519. RFC 9591 specifies the FROST threshold signing protocol and an Ed25519 ciphersuite. [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
- **MST** requires secp256k1 ECDSA for transaction signatures with EIP-2 low-S constraint. [Lockness CGGMP24 implementation notes](https://github.com/LFDT-Lockness/cggmp21#auxiliary-info-generation)
- **Bitcoin** uses BIP-341 Taproot rules and BIP-340-compatible Schnorr signatures. [BIP 341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) [ZF FROST audit scope](https://github.com/ZcashFoundation/frost#ncc-audit)
