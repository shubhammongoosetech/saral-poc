import { describe, it, expect } from 'vitest';
import {
  SaralClient,
  SaralError,
  validateChainCurveCompatibility,
  isValidEvmAddress,
  isValidBitcoinAddress,
  isValidSolanaAddress,
  toChecksumAddress,
} from '../../packages/saral-sdk/src';

describe('SARAL Protocol V3 — Architecture SDK Client', () => {
  it('instantiates SaralClient with default endpoints', () => {
    const client = new SaralClient();
    expect(client.coordinatorUrl).toBe('http://localhost:9001');
    expect(client.authServerUrl).toBe('http://localhost:3001');
  });

  it('accepts custom coordinator and auth server URLs', () => {
    const client = new SaralClient({
      coordinatorUrl: 'http://custom-coordinator:9002',
      authServerUrl: 'http://custom-auth:3002',
      token: 'custom-test-token',
    });
    expect(client.coordinatorUrl).toBe('http://custom-coordinator:9002');
    expect(client.authServerUrl).toBe('http://custom-auth:3002');
    expect(client.token).toBe('custom-test-token');
  });

  it('formats JSON-RPC payload correctly and handles SaralError', () => {
    const err = new SaralError('NOT_IMPLEMENTED', -32000, { stub: true });
    expect(err.name).toBe('SaralError');
    expect(err.code).toBe(-32000);
    expect(err.message).toBe('NOT_IMPLEMENTED');
    expect(err.data).toEqual({ stub: true });
  });

  it('exposes all required architecture SDK methods', () => {
    const client = new SaralClient();
    expect(typeof client.getNetworkStatus).toBe('function');
    expect(typeof client.getDomainStatus).toBe('function');
    expect(typeof client.getCoordinatorStatus).toBe('function');
    expect(typeof client.getNodes).toBe('function');
    expect(typeof client.getPeers).toBe('function');
    expect(typeof client.getTopology).toBe('function');
    expect(typeof client.probeNetwork).toBe('function');
    expect(typeof client.sendRelayMessage).toBe('function');
    expect(typeof client.getRelayAuditLog).toBe('function');
    expect(typeof client.getRelayDeliveryStatus).toBe('function');
    expect(typeof client.authenticate).toBe('function');
    // AVSS & Proactive Cryptosystems methods
    expect(typeof client.createAVSSSession).toBe('function');
    expect(typeof client.getAVSSSessionStatus).toBe('function');
    expect(typeof client.getAVSSParticipants).toBe('function');
    expect(typeof client.getAVSSCommitments).toBe('function');
    expect(typeof client.getAVSSVerificationStatus).toBe('function');
    expect(typeof client.getProactiveEpochStatus).toBe('function');
    expect(typeof client.requestProactiveRefresh).toBe('function');
    expect(typeof client.getRefreshStatus).toBe('function');
    // DKG methods
    expect(typeof client.startDkg).toBe('function');
    expect(typeof client.getDkgStatus).toBe('function');
    expect(typeof client.getDkgParticipants).toBe('function');
    expect(typeof client.getDkgPublicKey).toBe('function');
    expect(typeof client.getDkgVerificationStatus).toBe('function');
    // Web3 Wallet methods
    expect(typeof client.createWallet).toBe('function');
    expect(typeof client.getWallets).toBe('function');
    expect(typeof client.getWalletById).toBe('function');
    expect(typeof client.getWalletAddress).toBe('function');
  });

  it('strictly validates blockchain curve compatibility against DKG key curves', () => {
    // Ethereum requires secp256k1 -> Incompatible with NIST P-256
    const ethCheck = validateChainCurveCompatibility('ethereum', 'NIST P-256');
    expect(ethCheck.compatible).toBe(false);
    expect(ethCheck.requiredCurve).toBe('secp256k1');
    expect(ethCheck.reason).toContain('Incompatible Curve');

    // Bitcoin requires secp256k1 -> Incompatible with NIST P-256
    const btcCheck = validateChainCurveCompatibility('bitcoin', 'NIST P-256');
    expect(btcCheck.compatible).toBe(false);
    expect(btcCheck.requiredCurve).toBe('secp256k1');

    // Solana requires Ed25519 -> Incompatible with NIST P-256
    const solCheck = validateChainCurveCompatibility('solana', 'NIST P-256');
    expect(solCheck.compatible).toBe(false);
    expect(solCheck.requiredCurve).toBe('ed25519');

    // Passkey / WebAuthn account -> Compatible with NIST P-256
    const passkeyCheck = validateChainCurveCompatibility('passkey-p256', 'NIST P-256');
    expect(passkeyCheck.compatible).toBe(true);
    expect(passkeyCheck.requiredCurve).toBe('nist-p256');
  });

  it('validates standard blockchain address formats and checksums', () => {
    // EVM Address Validation
    const sampleEvm = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
    expect(isValidEvmAddress(sampleEvm)).toBe(true);
    expect(isValidEvmAddress('0xinvalid')).toBe(false);

    // EIP-55 Checksum
    const checksummed = toChecksumAddress('0xd8da6bf26964af9d7eed9e03e53415d37aa96045');
    expect(checksummed.startsWith('0x')).toBe(true);
    expect(checksummed.length).toBe(42);

    // Bitcoin Taproot Bech32m Address
    expect(isValidBitcoinAddress('bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0')).toBe(true);
    expect(isValidBitcoinAddress('tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0', 'testnet')).toBe(true);

    // Solana Base58 Address
    expect(isValidSolanaAddress('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')).toBe(true);
  });
});

