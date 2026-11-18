import { Router, Request, Response } from 'express';
import { KeyManager } from '../auth/token';

const router = Router();
const keyManager = KeyManager.getInstance();

// Health endpoint
router.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'saral-auth-server',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
});

// Development authentication endpoint
router.post('/auth/token', (req: Request, res: Response) => {
  const subject = req.body?.subject || req.body?.username || 'dev-operator-1';
  const role = req.body?.role || 'admin';
  const token = keyManager.issueToken(subject, role);

  res.json({
    success: true,
    token,
    tokenType: 'Bearer',
    expiresIn: 3600,
    subject,
    issuer: 'saral-auth-server',
  });
});

// Alias for /api/auth/token
router.post('/api/auth/token', (req: Request, res: Response) => {
  const subject = req.body?.subject || req.body?.username || 'dev-operator-1';
  const role = req.body?.role || 'admin';
  const token = keyManager.issueToken(subject, role);

  res.json({
    success: true,
    token,
    tokenType: 'Bearer',
    expiresIn: 3600,
    subject,
    issuer: 'saral-auth-server',
  });
});

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
  });
});

export default router;
