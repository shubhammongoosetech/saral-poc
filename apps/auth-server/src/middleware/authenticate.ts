import { Request, Response, NextFunction } from 'express';
import { KeyManager } from '../auth/token';

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

export function authenticate(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ success: false, error: 'Unauthorized: Missing Bearer token' });
    return;
  }

  const token = authHeader.substring(7).trim();
  try {
    const decoded = keyManager.verifyToken(token) as any;

    req.user = {
      userId: decoded.userId || decoded.sub,
      role: decoded.domainRole || decoded.role || 'operator',
      mfaVerified: !!decoded.mfaVerified,
    };
    next();
  } catch (err: any) {
    res.status(401).json({ success: false, error: 'Unauthorized: Invalid or expired token' });
  }
}
