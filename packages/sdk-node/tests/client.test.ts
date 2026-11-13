import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SaralClient } from '../src';
import { SaralError, PolicyDeniedError } from '@saral/sdk-core';

describe('SaralClient (sdk-node)', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('rejects insecure HTTP baseUrl in production mode', () => {
    expect(
      () =>
        new SaralClient({
          baseUrl: 'http://api.saral.network',
        })
    ).toThrowError(SaralError);

    try {
      new SaralClient({ baseUrl: 'http://api.saral.network' });
    } catch (err: any) {
      expect(err.code).toBe('INVALID_CONFIG');
      expect(err.message).toContain('HTTPS');
    }
  });

  it('allows HTTP on localhost for local testing', () => {
    expect(
      () =>
        new SaralClient({
          baseUrl: 'http://localhost:3001',
        })
    ).not.toThrow();

    expect(
      () =>
        new SaralClient({
          baseUrl: 'http://127.0.0.1:3001',
        })
    ).not.toThrow();
  });

  it('maps backend policy denial into typed PolicyDeniedError', async () => {
    const client = new SaralClient({
      baseUrl: 'http://localhost:3001',
      getAuthToken: () => 'mock-jwt-token',
    });

    // Mock fetch returning 403 Access Denied
    global.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      statusText: 'Forbidden',
      text: vi.fn().mockResolvedValue(
        JSON.stringify({
          error: 'Access Denied: Attempt outside permitted working hours (09:00 - 18:00)',
        })
      ),
    }) as any;

    const dummyPreview = {
      chain: 'mst-testnet',
      curve: 'secp256k1' as const,
      from: '0x1111111111111111111111111111111111111111',
      to: '0x2222222222222222222222222222222222222222',
      amount: '0.1',
      fee: '0.000021',
      hashToSign: '0xabcdef',
      expiresAt: Date.now() + 60_000,
      unsignedTx: {
        chainId: 'mst-testnet',
        curve: 'secp256k1' as const,
        rawBytes: new Uint8Array(10),
        hashToSign: new Uint8Array(32),
        metadata: {},
      },
    };

    await expect(client.signAndSend(dummyPreview)).rejects.toThrowError(PolicyDeniedError);
  });

  it('signs and sends when 3 domains are satisfied', async () => {
    const client = new SaralClient({
      baseUrl: 'http://localhost:3001',
      getAuthToken: () => 'mock-jwt-token',
    });

    global.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: vi.fn().mockResolvedValue(
        JSON.stringify({
          success: true,
          broadcasted: true,
          txHash: '0x9999999999999999999999999999999999999999999999999999999999999999',
          message: 'Transaction broadcasted',
          explorerUrl: 'https://testnet.mstscan.com/tx/0x999',
          domainsSigned: ['foundation', 'public', 'private'],
        })
      ),
    }) as any;

    const dummyPreview = {
      chain: 'mst-testnet',
      curve: 'secp256k1' as const,
      from: '0x1111111111111111111111111111111111111111',
      to: '0x2222222222222222222222222222222222222222',
      amount: '0.1',
      fee: '0.000021',
      hashToSign: '0xabcdef',
      expiresAt: Date.now() + 60_000,
      unsignedTx: {
        chainId: 'mst-testnet',
        curve: 'secp256k1' as const,
        rawBytes: new Uint8Array(10),
        hashToSign: new Uint8Array(32),
        metadata: {},
      },
    };

    const res = await client.signAndSend(dummyPreview);
    expect(res.status).toBe('BROADCASTED');
    expect(res.domainsSigned).toEqual(['foundation', 'public', 'private']);
  });
});

