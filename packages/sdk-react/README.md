# @saral/sdk-react

React hooks, context provider, and headless workflow primitives for the SARAL 3-Domain Multi-Party Computation (MPC) non-custodial wallet.

## Installation

```bash
npm install @saral/sdk-react @saral/sdk-node @saral/sdk-core react react-dom
```

## Quick Start

### 1. Provider Setup

```tsx
import React from 'react';
import { SaralProvider } from '@saral/sdk-react';
import { SaralClient } from '@saral/sdk-node';

const client = new SaralClient({
  baseUrl: 'https://api.saral.network',
  getAuthToken: () => localStorage.getItem('token'),
});

export function App() {
  return (
    <SaralProvider client={client}>
      <WalletDashboard />
    </SaralProvider>
  );
}
```

### 2. Using Hooks

```tsx
import React, { useState } from 'react';
import {
  useChain,
  useBalance,
  usePrepareTransaction,
  useSignAndSend,
} from '@saral/sdk-react';

export function WalletDashboard() {
  const { chain, setChain } = useChain('mst-testnet');
  const { formatted: balance, loading: balanceLoading } = useBalance(chain.id);
  const { prepare, preview } = usePrepareTransaction();
  const { execute, state, signingDomain, result, error } = useSignAndSend();

  const handleSend = async () => {
    const prev = await prepare({
      chain: chain.id,
      to: '0x1234567890123456789012345678901234567890',
      amount: '0.01',
    });
    await execute(prev, { autoAcquireLocation: true });
  };

  return (
    <div>
      <h3>Chain: {chain.name}</h3>
      <p>Balance: {balanceLoading ? 'Loading...' : balance} {chain.symbol}</p>
      <button onClick={handleSend} disabled={state === 'signing' || state === 'broadcasting'}>
        Send
      </button>

      {state === 'signing' && <p>Signing with domain: {signingDomain}...</p>}
      {state === 'confirmed' && <p>Confirmed! Tx: {result?.txHash}</p>}
      {error && <p>Error: {error.message}</p>}
    </div>
  );
}
```

### 3. Headless `<SendFlow>` Component

```tsx
import React from 'react';
import { SendFlow } from '@saral/sdk-react';

export function QuickPayment() {
  return (
    <SendFlow
      chain="mst-testnet"
      to="0x1234567890123456789012345678901234567890"
      amount="0.05"
    >
      {({ state, preview, prepare, confirmAndSign, result, error }) => (
        <div>
          {!preview ? (
            <button onClick={() => prepare()}>Review Payment</button>
          ) : (
            <div>
              <p>Amount: {preview.amount}</p>
              <p>Estimated Gas: {preview.fee}</p>
              <p>Hash to sign: {preview.hashToSign}</p>
              <button onClick={() => confirmAndSign()}>Confirm & Sign</button>
            </div>
          )}
          {state === 'confirmed' && <p>Success: {result?.txHash}</p>}
          {error && <p>Failed: {error.message}</p>}
        </div>
      )}
    </SendFlow>
  );
}
```

## Error Codes Table

| Code | Description |
|---|---|
| `LOCATION_PERMISSION_DENIED` | Geolocation permission refused by browser user |
| `LOCATION_REQUIRED` | GPS location required for Zero-Trust policy gate |
| `POLICY_DENIED` | Context policy rejected signing (working hours, geofence, velocity) |
| `MFA_REQUIRED` | Operation requires 2FA / MFA token |
| `CHAIN_ADDRESS_MISMATCH` | Address format invalid for selected chain |
| `INSUFFICIENT_FUNDS` | Wallet balance insufficient for amount and gas fees |
| `DOMAIN_QUORUM_FAILED` | 3-domain authorization quorum was not achieved |
| `SIGNATURE_VERIFICATION_FAILED` | Aggregated signature public key check failed |
| `TRANSACTION_EXPIRED` | Prepared preview expired before confirmation |
| `RPC_ERROR` | Blockchain RPC error or broadcast rejection |

## Security Notes

1. **Zero Key Exposure**: No private keys exist on the browser. Signatures are gathered from 3 independent domains.
2. **Preview Integrity**: `hashToSign` is displayed to the user before signing authorization is sent.
3. **No Default Storage**: Authentication tokens are provided via user-defined getter callbacks (`getAuthToken`), never persisted or logged by the SDK.

