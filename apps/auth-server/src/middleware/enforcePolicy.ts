import { Request, Response, NextFunction } from 'express';
import { evaluateWorkingPolicy } from '../services/policyService';

export function enforcePolicy(req: Request, res: Response, next: NextFunction): void {
  if (!req.user) {
    res.status(401).json({ success: false, error: 'Unauthorized: Authentication required' });
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
