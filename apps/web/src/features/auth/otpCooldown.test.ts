import { describe, it, expect, beforeEach, vi } from 'vitest';
import { SESSION_STORE, hashTokenToFingerprint } from '@/shared/lib/storage';

describe('OTP Cooldown and Token Tracking', () => {
  beforeEach(() => {
    sessionStorage.clear();
    vi.useRealTimers();
  });

  it('generates a non-reversible hash fingerprint that never leaks raw token slices', () => {
    const rawToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_payload.signature_xyz';
    const fp = hashTokenToFingerprint(rawToken);

    expect(typeof fp).toBe('string');
    expect(fp.length).toBe(8);
    // Assert no substring of the raw token appears in the fingerprint
    expect(rawToken.includes(fp)).toBe(false);
    expect(fp.includes('sensitive')).toBe(false);
    expect(fp.includes('signature')).toBe(false);
  });

  it('allows sending MFA initially for a token', () => {
    const token = 'header.payloadA.signature';
    expect(SESSION_STORE.canSendMfa(token)).toBe(true);
    expect(SESSION_STORE.getRemainingMfaCooldown(token)).toBe(0);
  });

  it('records sent timestamp and enters 30s cooldown', () => {
    const token = 'header.payloadA.signature';
    const now = 1700000000000;
    vi.setSystemTime(now);

    SESSION_STORE.setMfaCodeSent(token);

    expect(SESSION_STORE.canSendMfa(token)).toBe(false);
    expect(SESSION_STORE.getRemainingMfaCooldown(token)).toBe(30);

    // Fast forward 10 seconds
    vi.setSystemTime(now + 10000);
    expect(SESSION_STORE.canSendMfa(token)).toBe(false);
    expect(SESSION_STORE.getRemainingMfaCooldown(token)).toBe(20);

    // Fast forward to 30 seconds
    vi.setSystemTime(now + 30000);
    expect(SESSION_STORE.canSendMfa(token)).toBe(true);
    expect(SESSION_STORE.getRemainingMfaCooldown(token)).toBe(0);
  });

  it('scopes MFA send marker strictly per token', () => {
    const token1 = 'header.payload1.signature';
    const token2 = 'header.payload2.signature';

    SESSION_STORE.setMfaCodeSent(token1);

    expect(SESSION_STORE.canSendMfa(token1)).toBe(false);
    // New login token has not had an OTP sent yet
    expect(SESSION_STORE.canSendMfa(token2)).toBe(true);
    expect(SESSION_STORE.getRemainingMfaCooldown(token2)).toBe(0);
  });

  it('clears all MFA markers on clearMfaMarkers()', () => {
    const token1 = 'header.token1.sig';
    const token2 = 'header.token2.sig';

    SESSION_STORE.setMfaCodeSent(token1);
    SESSION_STORE.setMfaCodeSent(token2);

    expect(SESSION_STORE.canSendMfa(token1)).toBe(false);
    expect(SESSION_STORE.canSendMfa(token2)).toBe(false);

    SESSION_STORE.clearMfaMarkers();

    expect(SESSION_STORE.canSendMfa(token1)).toBe(true);
    expect(SESSION_STORE.canSendMfa(token2)).toBe(true);
  });
});
