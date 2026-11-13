# @saral/sdk-core

Shared types, errors, chain registry, multi-chain adapters, and 3-domain MPC signing backends for the SARAL cryptographic key management system.

## Installation

```bash
npm install @saral/sdk-core
```

## Quick Start

```typescript
import {
  ChainRegistry,
  EvmAdapter,
  EcdsaSigner,
  MST_TESTNET,
} from '@saral/sdk-core';

// 1. Initialize registry and adapters
const registry = new ChainRegistry();
const chain = registry.getChain('mst-testnet');
const adapter = new EvmAdapter(chain);

// 2. Validate recipient address
registry.assertValidAddress('mst-testnet', '0x1234567890123456789012345678901234567890');

// 3. 3-Domain MPC signature aggregation
const signer = new EcdsaSigner();
const signature = await signer.aggregate(
  {
    r: '0x...',
    expectedPublicKey: '0x...',
    domains: {
      foundation: { domain: 'foundation', s: '0x...' },
      public: { domain: 'public', s: '0x...' },
      private: { domain: 'private', s: '0x...' },
    },
  },
  hashToSign
);
```

## Error Codes Table

| Code | Description |
|---|---|
| `CHAIN_NOT_FOUND` | Target chain identifier is not registered |
| `CHAIN_ADDRESS_MISMATCH` | Recipient address format does not match the target chain |
| `INVALID_CONFIG` | Invalid chain or client configuration passed to SDK |
| `DOMAIN_QUORUM_FAILED` | One or more of the 3 required domains (Foundation, Public, Private) failed to produce a valid partial signature |
| `SIGNATURE_VERIFICATION_FAILED` | Aggregated signature public key recovery failed to match the expected public key |
| `NOT_IMPLEMENTED` | Cryptographic scheme or operation is not yet available |
| `RPC_ERROR` | Upstream blockchain JSON-RPC node failure or rejection |
| `INSUFFICIENT_FUNDS` | Wallet balance is lower than amount plus estimated fees |
| `NONCE_FETCH_FAILED` | Could not determine current account nonce from RPC |
| `TRANSACTION_EXPIRED` | Prepared transaction passed its expiration time window |
| `BLOCKHASH_EXPIRED` | Solana blockhash expired before signing completed |
| `POLICY_DENIED` | Zero-Trust context policy gate rejected authorization (working hours, geofence, velocity) |
| `MFA_REQUIRED` | Operation requires multi-factor authentication token |
| `LOCATION_REQUIRED` | GPS coordinates are required by current policy |
| `LOCATION_PERMISSION_DENIED` | User denied browser geolocation permission |
| `AUTH_REQUIRED` | Bearer authentication token is missing or expired |
| `NETWORK_ERROR` | Network or HTTP connection failure |
| `IDEMPOTENCY_CONFLICT` | Replay protection error |

## Security Notes

1. **Zero Private Key Reconstruction**: Private keys and secret shares are never received, stored, or reconstructed in this SDK. The SDK only accepts threshold-satisfied partial signatures from the 3 independent domains.
2. **3-of-3 Domain Quorum**: Transactions cannot be authorized without verifiable contributions from Foundation, Public, and Private domains simultaneously.
3. **Fail-Closed Verification**: The aggregated signature is checked against the expected public key locally before the transaction is broadcast to the network.
4. **Memory Hygiene**: Use `zeroize()` on sensitive buffers immediately after cryptographic operations.

