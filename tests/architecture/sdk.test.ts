import { describe, it, expect } from 'vitest';
import { SaralClient, SaralError } from '../../packages/saral-sdk/src';

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
  });
});

