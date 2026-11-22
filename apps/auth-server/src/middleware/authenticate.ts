import { Request, Response, NextFunction } from 'express';
import { InvalidAccountSession, validateAccountSession } from '../auth/accountSession';

export interface AuthenticatedUser {
  userId: string;
  role: string;
  mfaVerified: boolean;
  sessionId: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

export async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ success: false, error: 'Unauthorized: Missing Bearer token' });
    return;
  }

  const token = authHeader.substring(7).trim();
  try {
    const decoded = await validateAccountSession(token);

    req.user = {
      userId: decoded.sub,
      role: 'operator',
      mfaVerified: decoded.mfaVerified,
      sessionId: decoded.nonce!,
    };
  } catch (error) {
    if (error instanceof InvalidAccountSession) {
      res.status(401).json({ success: false, error: 'Unauthorized: Invalid or expired token' });
    } else {
      res.status(503).json({ success: false, error: 'The sign-in service is temporarily unavailable' });
    }
    return;
  }
  next();
}
