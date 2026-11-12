import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, verifyToken, AuthPayload } from '../utils/jwt';

// Extend Express Request interface to include user and requestId
declare global {
  namespace Express {
    interface Request {
      user?: AuthPayload;
      requestId?: string;
    }
  }
}

/**
 * Ensures request has a valid JWT token.
 *
 * Token resolution order (transition period — TODO: remove Bearer header
 * support once all clients send cookies):
 *   1. req.cookies.access_token  (httpOnly cookie — preferred, D-07)
 *   2. Authorization: Bearer <token>  (legacy support)
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  let token: string | undefined;

  // 1. Prefer explicit Authorization: Bearer header so active client tokens
  //    (account switches or API callers) are never overridden by stale cookies
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const bearerToken = authHeader.slice(7).trim();
    if (bearerToken) {
      token = bearerToken;
    }
  }

  // 2. Fall back to httpOnly cookie-based token
  if (!token && req.cookies && typeof req.cookies.access_token === 'string') {
    token = req.cookies.access_token as string;
  }

  if (!token) {
    res.status(401).json({ error: 'Authentication required.' });
    return;
  }

  try {
    // verifyAccessToken and verifyToken are identical post-rewrite
    const payload = verifyAccessToken(token);
    req.user = payload;
    next();
  } catch {
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

// Re-export verifyToken for any legacy callers that import it from authGuard
export { verifyToken };
