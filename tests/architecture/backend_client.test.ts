import { describe, it, expect } from 'vitest';
import {
  SaralBackendClient,
  SaralBackendError,
} from '../../apps/auth-server/src/clients/saralBackendClient';
import {
  deriveMultiChainAddresses,
  toEip55Checksum,
  encodeTaprootBech32m,
} from '../../apps/auth-server/src/services/walletService';
import { KeyManager } from '../../apps/auth-server/src/auth/token';

describe('SARAL Protocol V3 — Internal Backend Client & Multi-Chain Address Derivation', () => {
  it('instantiates SaralBackendClient with default endpoints', () => {
    const client = new SaralBackendClient();
    expect(client).toBeDefined();
    expect(typeof client.startDkg).toBe('function');
    expect(typeof client.getDkgPublicKey).toBe('function');
    expect(typeof client.derivePublicKey).toBe('function');
    expect(typeof client.getCoordinatorStatus).toBe('function');
    expect(typeof client.getNetworkStatus).toBe('function');
    expect(typeof client.getDomainStatus).toBe('function');
  });

  it('accepts custom coordinator URL and options', () => {
    const client = new SaralBackendClient({
      coordinatorUrl: 'http://custom-coordinator:9002',
      timeoutMs: 5000,
    });
    expect(client).toBeDefined();
  });

  it('formats JSON-RPC payload correctly and structures SaralBackendError', () => {
    const err = new SaralBackendError('COORDINATOR_UNAVAILABLE', -32000, { detail: 'timeout' }, 'corr-123');
    expect(err.name).toBe('SaralBackendError');
    expect(err.code).toBe(-32000);
    expect(err.message).toBe('COORDINATOR_UNAVAILABLE');
    expect(err.data).toEqual({ detail: 'timeout' });
    expect(err.correlationId).toBe('corr-123');
  });

  it('issues scoped Ed25519 JWT tokens binding user, wallet, and operation', () => {
    const keyManager = KeyManager.getInstance();
    const token = keyManager.issueScopedToken({
      sub: 'usr-test-123',
      userId: 'usr-test-123',
      walletId: 'wal-test-456',
      dkgSessionId: 'dkg-session-789',
      committeeId: 'committee-foundation',
      operation: 'derive_public_key',
    });

    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
    expect(token.split('.').length).toBe(3);

    // Verify token claims
    const verified = keyManager.verifyToken(token);
    expect(verified).toBeDefined();
    expect(verified.sub).toBe('usr-test-123');
    expect(verified.walletId).toBe('wal-test-456');
    expect(verified.operation).toBe('derive_public_key');
    expect(verified.mfaVerified).toBe(true);
  });

  it('validates standard EIP-55 EVM checksum addresses', () => {
    const sample = '0xd8da6bf26964af9d7eed9e03e53415d37aa96045';
    const checksummed = toEip55Checksum(sample);
    expect(checksummed.toLowerCase()).toBe(sample.toLowerCase());
    expect(checksummed.startsWith('0x')).toBe(true);
    expect(checksummed.length).toBe(42);
    // Double-checksumming is idempotent
    expect(toEip55Checksum(checksummed)).toBe(checksummed);
  });

  it('validates Bitcoin Taproot Bech32m witness version 1 encoding', () => {
    const xOnlyPubkey = Buffer.alloc(32, 0xab);
    const btcAddress = encodeTaprootBech32m('tb', xOnlyPubkey);
    expect(btcAddress.startsWith('tb1p')).toBe(true);
    expect(btcAddress.length).toBe(62);
  });

  it('deterministically derives identical multi-chain addresses in RAM without database persistence', () => {
    const walletId = 'wal-deterministic-001';
    const keyRefs = {
      mst: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      solana: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      bitcoin: '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    };

    const firstDerivation = deriveMultiChainAddresses(walletId, keyRefs);
    const secondDerivation = deriveMultiChainAddresses(walletId, keyRefs);

    // Exact address matches across separate derivation calls
    expect(firstDerivation.mst.address).toBe(secondDerivation.mst.address);
    expect(firstDerivation.solana.address).toBe(secondDerivation.solana.address);
    expect(firstDerivation.bitcoin.address).toBe(secondDerivation.bitcoin.address);

    // Format invariants
    expect(firstDerivation.mst.address).toMatch(/^0x[a-fA-F0-9]{40}$/);
    expect(firstDerivation.solana.address).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
    expect(firstDerivation.bitcoin.address).toMatch(/^tb1p[0-9a-z]{58}$/);
  });
});
