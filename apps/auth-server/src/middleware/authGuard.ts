/**
 * SARAL Protocol V3 — Authentication & Policy Guards
 */

import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { KeyManager } from '../auth/token';
import { evaluateWorkingPolicy } from '../services/policyService';

const keyManager = KeyManager.getInstance();

export interface AuthenticatedUser {
  userId: string;
  role: string;
  mfaVerified: boolean;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

/**
 * Validates JWT bearer token against the Auth Server's RSA public key.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ success: false, error: 'Unauthorized: Missing Bearer token' });
    return;
  }

  const token = authHeader.substring(7).trim();
  try {
    const decoded = jwt.verify(token, keyManager.publicKeyPem, {
      algorithms: ['RS256'],
    }) as any;

    req.user = {
      userId: decoded.sub || decoded.userId,
      role: decoded.domainRole || decoded.role || 'operator',
      mfaVerified: !!decoded.mfaVerified,
    };
    next();
  } catch (err: any) {
    res.status(401).json({ success: false, error: 'Unauthorized: Invalid or expired token' });
  }
}

/**
 * Requires that MFA verification has succeeded.
 */
export function requireMfa(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ success: false, error: 'Unauthorized: Authentication required' });
    return;
  }

  if (!req.user.mfaVerified) {
    res.status(403).json({
      success: false,
      error: 'Forbidden: Second-factor MFA verification required',
      needsMfa: true,
    });
    return;
  }

  next();
}

/**
 * Evaluates working policy for sensitive operations.
 */
export function requireWorkingPolicy(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ success: false, error: 'Unauthorized' });
    return;
  }

  const lat = req.body?.lat !== undefined ? Number(req.body.lat) : undefined;
  const lng = req.body?.lng !== undefined ? Number(req.body.lng) : undefined;

  const result = evaluateWorkingPolicy(req.user.userId, lat, lng);
  if (!result.allowed) {
    res.status(403).json({
      success: false,
      error: result.reason || 'Access denied by Working Policy',
      policyResult: result,
    });
    return;
  }

  next();
}
