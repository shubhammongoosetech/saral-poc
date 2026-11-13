# @saral/sdk-node

Node.js / server SDK client for the SARAL 3-Domain Multi-Party Computation (MPC) non-custodial wallet.

## Installation

```bash
npm install @saral/sdk-node
```

## Quick Start

```typescript
import { SaralClient } from '@saral/sdk-node';

// 1. Initialize client
const saral = new SaralClient({
  baseUrl: 'https://api.saral.network',
  getAuthToken: () => process.env.SARAL_JWT_TOKEN || null,
});

// 2. Prepare transaction preview (determines curve, fee, and hash to sign)
const preview = await saral.prepareTransaction({
  chain: 'mst-testnet',
  to: '0x1234567890123456789012345678901234567890',
  amount: '0.05',
});

console.log('Hash to sign:', preview.hashToSign);
console.log('Estimated fee:', preview.fee);

// 3. Authorize, collect 3-domain signatures, aggregate, and broadcast
const result = await saral.signAndSend(preview, {
  location: { lat: 12.9716, lng: 77.5946 }, // Bangalore coordinates
});

console.log('Transaction hash:', result.txHash);
console.log('Explorer URL:', result.explorerUrl);
console.log('Domains signed:', result.domainsSigned); // ['foundation', 'public', 'private']
```

## Error Codes Table

| Code | Description |
|---|---|
| `CHAIN_NOT_FOUND` | Target chain identifier is not registered |
| `CHAIN_ADDRESS_MISMATCH` | Recipient address format does not match target chain |
| `INVALID_CONFIG` | Insecure HTTP baseUrl or invalid client parameters |
| `DOMAIN_QUORUM_FAILED` | One or more of the 3 required domains (Foundation, Public, Private) failed to produce a valid partial signature |
| `SIGNATURE_VERIFICATION_FAILED` | Aggregated signature verification against expected public key failed |
| `NOT_IMPLEMENTED` | Cryptographic scheme or curve operation is not yet available |
| `RPC_ERROR` | Upstream blockchain RPC node failure or transaction rejection |
| `INSUFFICIENT_FUNDS` | Wallet balance is lower than amount plus estimated fees |
| `NONCE_FETCH_FAILED` | Could not determine current account nonce from RPC |
| `TRANSACTION_EXPIRED` | Prepared transaction passed its expiration window |
| `POLICY_DENIED` | Zero-Trust context policy gate rejected authorization (working hours, geofence, velocity) |
| `MFA_REQUIRED` | Operation requires multi-factor authentication token |
| `LOCATION_REQUIRED` | GPS coordinates are required by policy |
| `AUTH_REQUIRED` | Bearer authentication token is missing or expired |
| `NETWORK_ERROR` | Network or HTTP connection failure |

## Security Notes

1. **Zero Key Storage**: No private keys or secret shares are ever received or stored by the client. The client receives only partial signatures from independent nodes across Foundation, Public, and Private domains.
2. **Strict Quorum Verification**: The client verifies that all 3 domains contributed valid signatures before combining and broadcasting.
3. **Transport Security**: Requires HTTPS for all endpoints (HTTP permitted solely for `localhost` development).
4. **Idempotency**: Pass `idempotencyKey` in `signAndSend` to guard against duplicate payment submissions.

