import { Request, Response, NextFunction } from 'express';

export function requireMfa(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ success: false, error: 'Unauthorized: Authentication required' });
    return;
  }

  if (!req.user.mfaVerified) {
    res.status(403).json({
      success: false,
      error: 'MFA_REQUIRED',
      message: 'Multi-Factor Authentication verification required to perform this action',
    });
    return;
  }

  next();
}
