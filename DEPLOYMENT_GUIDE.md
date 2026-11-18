# SARAL POC — Production Deployment & Node Cluster Operations Guide

**Document Version:** 1.0  
**Author:** Principal Distributed Systems & DevOps Engineer  
**Date:** November 18, 2026  

---

## 1. System Requirements & Architecture

The SARAL multi-chain threshold system is designed to run across multiple isolated nodes divided strictly into three administrative domains:

```
+-------------------------------------------------------------------------------------------------------+
| Domain           | Default Nodes | Quorum | Purpose                        | Host Environments        |
+-------------------------------------------------------------------------------------------------------+
| **FOUNDATION**   | 5 nodes       | 3      | Institutional Policy / Audit   | Cloud / Dedicated VM     |
| **PUBLIC**       | 5 nodes       | 3      | Independent Validators         | Distributed Cloud / Bare |
| **PRIVATE**      | 5 nodes       | 3      | Sovereign User Enclave         | User Enclaves / Devices  |
+-------------------------------------------------------------------------------------------------------+
```

### Host Requirements (Per Node)
- **OS:** Ubuntu 22.04 LTS+, Debian 12+, macOS, or Windows Server 2022.
- **Node.js:** v20.x or v22.x LTS.
- **Memory:** Minimum 1 GB RAM per node daemon process.
- **Storage:** Minimum 10 GB persistent storage with SSD for the encrypted Node Vault.
- **Network:** Low-latency TCP connectivity on configured P2P ports (e.g. 19101–19115).

---

## 2. Environment Configuration

Create a `.env` file in `backend/` using the following production template:

```env
# Application & API
NODE_ENV=production
PORT=5000
API_PREFIX=/api/v1
CORS_ORIGIN=https://app.saral.network

# Security & Secrets
JWT_SECRET=generate_with_openssl_rand_hex_64
JWT_EXPIRES_IN=15m
ENCRYPTION_MASTER_KEY=generate_with_openssl_rand_hex_32
ACCESS_TOKEN_TTL_SECONDS=900

# Database (PostgreSQL for metadata ONLY — ZERO keys stored)
DATABASE_URL=postgresql://saral_admin:strong_password@postgres:5432/saral_poc?schema=public

# Blockchain RPC Endpoints
# EVM / MST Testnet
RPC_URL=https://testnetrpc.mstblockchain.com
CHAIN_ID=91562037

# Solana Devnet
SOLANA_RPC_URL=https://api.devnet.solana.com
SOLANA_NETWORK=devnet

# Bitcoin Testnet / Regtest
BITCOIN_NETWORK=testnet

# 3-Domain Topology Configuration
FOUNDATION_NODES=5
FOUNDATION_THRESHOLD=3
PUBLIC_NODES=5
PUBLIC_THRESHOLD=3
PRIVATE_NODES=5
PRIVATE_THRESHOLD=3

# P2P Node Cluster Settings
NODE_STORAGE_DRIVER=sandbox # Options: 'sandbox' | 'docker' | 'remote'
NODE_SANDBOX_BASE_DIR=/var/saral/vaults
P2P_BASE_PORT=19100
P2P_CONNECT_TIMEOUT_MS=8000
P2P_ENVELOPE_MAX_AGE_SECONDS=30
```

---

## 3. Node Vault Setup & Permissions

The Node Vault holds participant identity keys and threshold secret shares. It must be locked down using strict filesystem permissions:

```bash
# 1. Create base directory for node vaults
sudo mkdir -p /var/saral/vaults
sudo chown -R saral:saral /var/saral/vaults
sudo chmod 700 /var/saral/vaults

# 2. Files created by node daemons automatically enforce mode 0o600
# share_frost_ed25519_<sessionId>.json (-rw-------)
# share_frost_taproot_<sessionId>.json (-rw-------)
# share_cggmp21_<sessionId>.json       (-rw-------)
# identity.json                        (-rw-------)
```

---

## 4. Starting the P2P Node Cluster

### Option A: Docker Compose Multi-Container Deployment

SARAL provides a containerized orchestration setup in `backend/docker-compose.generated.yml`:

```bash
# Build and start all 15 node daemons + PostgreSQL + Coordinator API
docker-compose -f backend/docker-compose.generated.yml up -d --build

# Inspect running cluster containers
docker ps --filter "name=saral-"

# Output will list:
# saral-foundation-1 ... saral-foundation-5
# saral-public-1     ... saral-public-5
# saral-private-1    ... saral-private-5
```

### Option B: Standalone Process Daemon Orchestration

For environments using PM2 or systemd:

```bash
# Start an individual node daemon:
npx tsx backend/src/tss/p2p/P2PNodeDaemon.ts \
  --nodeId=saral-foundation-1 \
  --domain=FOUNDATION \
  --shareIndex=1 \
  --port=19101 \
  --vaultDir=/var/saral/vaults/saral-foundation-1

# Start the Coordinator / API Service:
npm --prefix backend run build
npm --prefix backend start
```

---

## 5. Operational Workflows

### A. Initializing a New Multi-Chain Wallet (Dealerless DKG)

```typescript
import { multiChainDkgCoordinator } from './src/tss/dkg';

// 1. Define participants across 3 domains
const participants = [
  { id: 'f1', index: 1, domain: 'FOUNDATION', identityPublicKeyHex: '...' },
  { id: 'f2', index: 2, domain: 'FOUNDATION', identityPublicKeyHex: '...' },
  { id: 'p1', index: 3, domain: 'PUBLIC', identityPublicKeyHex: '...' },
  { id: 'p2', index: 4, domain: 'PUBLIC', identityPublicKeyHex: '...' },
  { id: 'u1', index: 5, domain: 'PRIVATE', identityPublicKeyHex: '...' },
  { id: 'u2', index: 6, domain: 'PRIVATE', identityPublicKeyHex: '...' },
];

const topology = {
  foundation: { count: 2, threshold: 1 },
  public: { count: 2, threshold: 1 },
  private: { count: 2, threshold: 1 },
};

// 2. Execute unified multi-chain DKG ceremony
const dkgResult = multiChainDkgCoordinator.executeUnifiedMultiChainDkg(
  `session-${Date.now()}`,
  participants,
  topology,
  'testnet'
);

// 3. Persist shares into isolated node vaults
for (const p of participants) {
  multiChainDkgCoordinator.persistSharesToVault(`/var/saral/vaults/${p.id}`, p.index, dkgResult);
}

console.log('Solana Address:', dkgResult.solana.address);
console.log('Bitcoin Taproot Address:', dkgResult.bitcoinTaproot.address);
console.log('Ethereum Address:', dkgResult.ethereum.address);
```

### B. Executing a Multi-Chain Transaction Signing Session

```typescript
import { threeDomainCoordinator } from './src/tss/domain/ThreeDomainCoordinator';
import { prepareSolanaTransferTransaction, applyFrostSignatureToSolanaTransaction } from './src/tss/protocols/frost-ed25519';

// 1. Prepare unsigned transaction
const prepared = prepareSolanaTransferTransaction({
  fromPubkey: dkgResult.solana.address,
  toPubkey: 'recipient_base58_address',
  lamports: 5000000n,
  recentBlockhash: recentBlockhashFromRpc,
});

// 2. Coordinate threshold signing across active nodes
const signResult = await threeDomainCoordinator.coordinateSigning({
  sessionId: `sign-${Date.now()}`,
  chain: 'solana',
  messageOrTx: prepared.messageBytes,
  domainTopology: topology,
  domainKeys: {
    foundationPublicKeyHex: '',
    publicPublicKeyHex: '',
    privatePublicKeyHex: '',
    aggregatedPublicKeyHex: dkgResult.solana.groupPublicKeyHex,
  },
  activeParticipants: activeQuorumNodes,
});

// 3. Attach FROST signature and broadcast to Solana Devnet
const { rawSignedTransaction } = applyFrostSignatureToSolanaTransaction(
  prepared.transaction,
  prepared.fromPubkey,
  {
    rawSignatureHex: signResult.rawSignatureHex,
    R_hex: signResult.rawSignatureHex.slice(0, 64),
    z_hex: signResult.rawSignatureHex.slice(64),
    groupPublicKeyHex: dkgResult.solana.groupPublicKeyHex,
    solanaAddress: dkgResult.solana.address,
  }
);
```

---

## 6. Health Monitoring & Troubleshooting

| Symptom | Root Cause | Remediation |
|---|---|---|
| `[3-Domain Policy Failure] ... threshold not met` | Fewer than $t_D$ nodes online in domain $D$ | Verify node daemon process status and network connectivity for that domain. |
| `EADDRINUSE` during node startup | Static port is already bound by another process | Use ephemeral port `0` or ensure unique port configuration per node. |
| `Taproot share verification failed` | Node submitted tampered scalar share or corrupted nonce | The identifiable abort system isolates the culpable node ID; replace with standby node. |
| `Connection timed out after 8000ms` | Network firewall blocking framed TCP packets | Check firewall / security group rules for P2P ports (19101–19115). |
