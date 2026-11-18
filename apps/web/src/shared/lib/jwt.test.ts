import { describe, it, expect } from 'vitest';
import { decodeJwtClaims, isTokenExpired } from './jwt';

function createMockJwt(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `${header}.${body}.mockSignature`;
}

describe('jwt claims decoding', () => {
  it('correctly decodes valid JWT claims with mfaVerified=true', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 900;
    const token = createMockJwt({
      id: 'usr_123',
      email: 'test@example.com',
      mfaVerified: true,
      exp: futureExp,
    });

    const claims = decodeJwtClaims(token);
    expect(claims).not.toBeNull();
    expect(claims?.userId).toBe('usr_123');
    expect(claims?.email).toBe('test@example.com');
    expect(claims?.mfaVerified).toBe(true);
    expect(claims?.exp).toBe(futureExp);
  });

  it('correctly decodes login token with mfaVerified=false', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 900;
    const token = createMockJwt({
      id: 'usr_456',
      mobile: '+919876543210',
      mfaVerified: false,
      exp: futureExp,
    });

    const claims = decodeJwtClaims(token);
    expect(claims).not.toBeNull();
    expect(claims?.userId).toBe('usr_456');
    expect(claims?.mfaVerified).toBe(false);
  });

  it('returns mfaVerified=false if claim is omitted', () => {
    const token = createMockJwt({ id: 'usr_789', exp: 1234567890 });
    const claims = decodeJwtClaims(token);
    expect(claims?.mfaVerified).toBe(false);
  });

  it('returns null for null or non-string inputs', () => {
    expect(decodeJwtClaims(null as unknown as string)).toBeNull();
    expect(decodeJwtClaims(undefined as unknown as string)).toBeNull();
    expect(decodeJwtClaims('')).toBeNull();
  });

  it('returns null for malformed JWT strings', () => {
    expect(decodeJwtClaims('not-a-jwt')).toBeNull();
    expect(decodeJwtClaims('part1.part2')).toBeNull();
    expect(decodeJwtClaims('header.invalid-base64-payload!!!.signature')).toBeNull();
  });
});

describe('isTokenExpired', () => {
  it('returns false for tokens expiring in the future', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 600;
    expect(isTokenExpired(futureExp)).toBe(false);
  });

  it('returns true for past expiration timestamps', () => {
    const pastExp = Math.floor(Date.now() / 1000) - 10;
    expect(isTokenExpired(pastExp)).toBe(true);
  });

  it('returns true for 0 or missing exp', () => {
    expect(isTokenExpired(0)).toBe(true);
  });
});
