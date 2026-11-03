import { Request, Response, NextFunction } from 'express';
import { verifyToken, AuthPayload } from '../utils/jwt';

// Extend Express Request interface to include user
declare global {
  namespace Express {
    interface Request {
      user?: AuthPayload;
    }
  }
}

/**
 * Ensures request has a valid JWT token
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required. Missing Bearer token.' });
    return;
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = verifyToken(token);
    req.user = payload;
    next();
  } catch (err: any) {
    res.status(401).json({ error: 'Invalid or expired session token.' });
  }
}

/**
 * Ensures user has completed second factor MFA verification
 */
export function requireMfa(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  if (!req.user.mfaVerified) {
    res.status(403).json({
      error: 'MFA verification required.',
      code: 'MFA_REQUIRED',
    });
    return;
  }

  next();
}
