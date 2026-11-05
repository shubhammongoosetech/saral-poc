import jwt, { SignOptions } from 'jsonwebtoken';
import { Response } from 'express';
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

export function verifyRefreshToken(token: string): { userId: string } {
  return jwt.verify(token, env.REFRESH_TOKEN_SECRET) as { userId: string };
}

// ---------------------------------------------------------------------------
// Cookie helpers (D-07: httpOnly Secure SameSite=Strict)
// ---------------------------------------------------------------------------

const IS_PRODUCTION = env.NODE_ENV === 'production';

export function setAuthCookies(
  res: Response,
  accessToken: string,
  refreshToken: string
): void {
  res.cookie('access_token', accessToken, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    maxAge: env.ACCESS_TOKEN_TTL_SECONDS * 1000,
    path: '/',
  });

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: IS_PRODUCTION,
    sameSite: 'strict',
    maxAge: env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
    path: '/api/auth',
  });
}

export function clearAuthCookies(res: Response): void {
  res.clearCookie('access_token', { path: '/' });
  res.clearCookie('refresh_token', { path: '/api/auth' });
}

// ---------------------------------------------------------------------------
// Legacy compatibility (kept for transition — TODO: remove once all callers
// switch to signAccessToken / cookie pattern)
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
