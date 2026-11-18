import { Router, Request, Response } from 'express';
import { KeyManager } from '../auth/token';

const router = Router();
const keyManager = KeyManager.getInstance();

// Health endpoint
router.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'saral-auth-server',
    version: '3.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

const handleTokenIssuance = (req: Request, res: Response) => {
  const isDev = process.env.NODE_ENV !== 'production' || process.env.ENABLE_DEV_AUTH === 'true';
  const adminSecret = process.env.SARAL_ADMIN_KEY || process.env.ADMIN_SECRET;

  const subject = req.body?.subject || req.body?.username || 'dev-operator-1';
  const requestedRole = req.body?.role || 'operator';

  // Security Rule 1: Restrict unauthenticated admin token issuance in non-dev environments
  if (!isDev) {
    const providedKey = req.headers['x-admin-key'] || req.body?.adminSecret;
    if (!adminSecret || providedKey !== adminSecret) {
      res.status(403).json({
        success: false,
        error: 'Forbidden: Unauthenticated administrative token issuance is restricted in non-development environments.',
      });
      return;
    }
  }

  // Validate allowed roles
  const validRoles = ['admin', 'operator', 'auditor', 'viewer'];
  const role = validRoles.includes(requestedRole) ? requestedRole : 'operator';

  const token = keyManager.issueToken(subject, role);

  res.json({
    success: true,
    token,
    tokenType: 'Bearer',
    expiresIn: 3600,
    subject,
    role,
    issuer: 'saral-auth-server',
    audience: 'saral-domain-coordinators',
  });
};

// Development & Standard authentication endpoints
router.post('/auth/token', handleTokenIssuance);
router.post('/api/auth/token', handleTokenIssuance);

// Public Key in PEM format
router.get('/auth/public-key', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/plain');
  res.send(keyManager.publicKeyPem);
});

// Public Key in JSON format
router.get('/auth/public-key.json', (_req: Request, res: Response) => {
  res.json({
    publicKeyPem: keyManager.publicKeyPem,
    algorithm: 'RS256',
    issuer: 'saral-auth-server',
    audience: 'saral-domain-coordinators',
  });
});

export default router;
