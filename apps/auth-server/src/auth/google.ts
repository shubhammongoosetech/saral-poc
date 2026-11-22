import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';

interface GoogleIdentity {
  subject: string;
  email?: string;
  name?: string;
}

const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
const GOOGLE_ISSUERS: [string, ...string[]] = ['https://accounts.google.com', 'accounts.google.com'];
const MIN_REFRESH_INTERVAL_MS = 30_000;
let keys = new Map<string, crypto.KeyObject>();
let refreshAfter = 0;
let expiresAt = 0;
let refresh: Promise<void> | undefined;

export function getGoogleClientId(): string | null {
  return env.isProd && !process.env.GOOGLE_CLIENT_ID ? null : env.GOOGLE_CLIENT_ID;
}

async function refreshGoogleKeys(): Promise<void> {
  const response = await fetch(GOOGLE_JWKS_URL, {
    redirect: 'error',
    signal: AbortSignal.timeout(5000),
  });
  if (!response.ok) throw new Error('Google sign-in is temporarily unavailable');

  const jwks = (await response.json()) as { keys?: Array<crypto.JsonWebKey & { kid?: string; alg?: string }> };
  const nextKeys = new Map<string, crypto.KeyObject>();
  for (const key of jwks.keys ?? []) {
    if (key.kty === 'RSA' && key.alg === 'RS256' && typeof key.kid === 'string') {
      nextKeys.set(key.kid, crypto.createPublicKey({ key, format: 'jwk' }));
    }
  }
  if (!nextKeys.size) throw new Error('Google sign-in is temporarily unavailable');

  const maxAge = response.headers.get('cache-control')?.match(/max-age=(\d+)/i)?.[1];
  const age = Number(response.headers.get('age') ?? '0');
  const ttl = Math.min(3600, Math.max(0, Number(maxAge ?? '300') - age));
  keys = nextKeys;
  expiresAt = Date.now() + ttl * 1000;
}

async function getGoogleKey(kid: string): Promise<crypto.KeyObject> {
  const now = Date.now();
  if (now >= expiresAt || !keys.has(kid)) {
    if (!refresh && now >= refreshAfter) {
      refreshAfter = now + MIN_REFRESH_INTERVAL_MS;
      refresh = refreshGoogleKeys().finally(() => { refresh = undefined; });
    }
    await refresh;
  }
  const key = keys.get(kid);
  if (!key || Date.now() >= expiresAt) throw new Error('Invalid Google credential token');
  return key;
}

export async function verifyGoogleIdentity(idToken: string, nonce?: string): Promise<GoogleIdentity> {
  if (typeof idToken !== 'string' || idToken.length > 8192) throw new Error('Invalid Google credential token');

  const decoded = jwt.decode(idToken, { complete: true });
  const kid = decoded?.header.kid;
  if (decoded?.header.alg !== 'RS256' || typeof kid !== 'string' || kid.length > 128) {
    throw new Error('Invalid Google credential token');
  }

  const clientId = getGoogleClientId();
  const unverified = decoded.payload;
  if (!clientId) throw new Error('Google sign-in is unavailable');
  if (!unverified || typeof unverified !== 'object' || unverified.aud !== clientId) throw new Error('Invalid Google credential token');
  const key = await getGoogleKey(kid);
  const claims = jwt.verify(idToken, key, { algorithms: ['RS256'], audience: clientId, issuer: GOOGLE_ISSUERS });
  if (
    typeof claims !== 'object' ||
    !Number.isSafeInteger(claims.exp) ||
    !Number.isSafeInteger(claims.iat) ||
    claims.iat! > Math.floor(Date.now() / 1000) + 30 ||
    typeof claims.sub !== 'string' || !claims.sub || claims.sub.length > 255 ||
    (claims.azp !== undefined && claims.azp !== clientId) ||
    (nonce !== undefined && claims.nonce !== nonce)
  ) {
    throw new Error('Invalid Google credential token');
  }

  return {
    subject: claims.sub,
    email: claims.email_verified === true && typeof claims.email === 'string' && claims.email.length <= 255
      ? claims.email.trim().toLowerCase()
      : undefined,
    name: typeof claims.name === 'string' ? claims.name.slice(0, 255) : undefined,
  };
}
