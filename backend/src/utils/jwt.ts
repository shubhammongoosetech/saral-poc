import jwt, { SignOptions } from 'jsonwebtoken';
import { env } from '../config/env';

export interface AuthPayload {
  userId: string;
  loginMethod: 'google' | 'mobile';
  mfaVerified: boolean;
  iat?: number;
  exp?: number;
}

// ---------------------------------------------------------------------------
// Access token (15-minute httpOnly cookie)
// ---------------------------------------------------------------------------

export function signAccessToken(
  payload: Omit<AuthPayload, 'iat' | 'exp'>
): string {
  const options: SignOptions = {
    expiresIn: env.ACCESS_TOKEN_TTL_SECONDS,
  };
  return jwt.sign(payload, env.JWT_SECRET, options);
}

export function verifyAccessToken(token: string): AuthPayload {
  return jwt.verify(token, env.JWT_SECRET) as AuthPayload;
}

// ---------------------------------------------------------------------------
// Refresh token (7-day httpOnly cookie)
// ---------------------------------------------------------------------------

export function signRefreshToken(userId: string): string {
  const options: SignOptions = {
    expiresIn: env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60,
  };
  return jwt.sign({ userId }, env.REFRESH_TOKEN_SECRET, options);
}

// ---------------------------------------------------------------------------
// Legacy compatibility
// ---------------------------------------------------------------------------

/** @deprecated Use signAccessToken() + setAuthCookies() instead */
export function signToken(
  payload: Omit<AuthPayload, 'iat' | 'exp'>,
  _expiresIn: string = '15m'
): string {
  return signAccessToken(payload);
}

/** @deprecated Use verifyAccessToken() instead */
export function verifyToken(token: string): AuthPayload {
  return verifyAccessToken(token);
}
