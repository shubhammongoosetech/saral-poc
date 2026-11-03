import jwt, { SignOptions } from 'jsonwebtoken';
import { env } from '../config/env';

export interface AuthPayload {
  userId: string;
  loginMethod: 'google' | 'mobile';
  mfaVerified: boolean;
  iat?: number;
  exp?: number;
}

export function signToken(
  payload: { userId: string; loginMethod: 'google' | 'mobile'; mfaVerified: boolean },
  expiresIn: string = '7d'
): string {
  const options: SignOptions = {
    expiresIn: expiresIn as any,
  };
  return jwt.sign(payload, env.JWT_SECRET, options);
}

export function verifyToken(token: string): AuthPayload {
  return jwt.verify(token, env.JWT_SECRET) as AuthPayload;
}
