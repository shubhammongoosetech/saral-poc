import { Router, Request, Response } from 'express';
import fs from 'fs';
import { KeyManager } from '../auth/token';

const router = Router();
const keyManager = KeyManager.getInstance();

let dynamicAdminSecret: string | null = null;

const INSECURE_DEFAULT_SECRETS = new Set([
  'saral-mesh-admin-secret-2026',
  'saral-internal-coordinator-secret',
  'saral-internal-secure-token-2026-v3',
  'saral-mesh-secure-internal-token-v3',
  'admin',
  'secret',
  'password',
  'default',
]);

function isKnownInsecureSecret(s: string): boolean {
  return INSECURE_DEFAULT_SECRETS.has(s.trim().toLowerCase());
}

function getAdminSecret(): string | null {
  if (dynamicAdminSecret) {
    return dynamicAdminSecret;
  }

  // 1. Docker secret file
  const secretPath = process.env.SARAL_ADMIN_KEY_FILE || '/run/secrets/saral_admin_key';
  try {
    if (fs.existsSync(secretPath)) {
      const content = fs.readFileSync(secretPath, 'utf8').trim();
      if (content && !isKnownInsecureSecret(content)) {
        dynamicAdminSecret = content;
        return content;
      }
    }
  } catch (_) {}

  // 2. Env variable
  const envKey = process.env.SARAL_ADMIN_KEY || process.env.ADMIN_SECRET;
  if (envKey) {
    const trimmed = envKey.trim();
    if (trimmed && !isKnownInsecureSecret(trimmed)) {
      dynamicAdminSecret = trimmed;
      return trimmed;
    }
  }

  // Strict fail-closed: No fallback to hardcoded administrative secret!
  return null;
}

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
  // Requirement 3: Restrict dev auth to explicitly enabled isolated local development environments
  const isLocalDevEnv =
    process.env.NODE_ENV === 'development' ||
    process.env.NODE_ENV === 'local' ||
    process.env.NODE_ENV === 'test';
  const isDevAuthExplicitlyEnabled = process.env.ENABLE_DEV_AUTH === 'true' && isLocalDevEnv;
  const adminSecret = getAdminSecret();

  const subject = req.body?.subject || req.body?.username || 'dev-operator-1';
  const requestedRole = req.body?.role || 'operator';
  const providedKey = req.headers['x-admin-key'] || req.body?.adminSecret;

  // If providedKey is a known default or insecure secret, reject immediately
  if (providedKey && typeof providedKey === 'string' && isKnownInsecureSecret(providedKey)) {
    res.status(403).json({
      success: false,
      error: 'Forbidden: Insecure or default administrative credentials rejected.',
    });
    return;
  }

  // Non-development environment or dev auth not explicitly enabled -> strictly require valid admin key
  if (!isDevAuthExplicitlyEnabled) {
    if (!adminSecret || !providedKey || providedKey !== adminSecret) {
      res.status(403).json({
        success: false,
        error: 'Forbidden: Development authentication is disabled. Authenticated administrative credentials required.',
      });
      return;
    }
  }

  // Admin role always requires administrative credentials
  if (requestedRole === 'admin') {
    if (!adminSecret || !providedKey || providedKey !== adminSecret) {
      res.status(403).json({
        success: false,
        error: 'Forbidden: Admin role issuance requires authenticated administrative secret credentials.',
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

// Credential rotation endpoint (Requirement 9)
router.post('/auth/rotate-admin-key', (req: Request, res: Response) => {
  const currentSecret = getAdminSecret();
  const providedCurrentKey = req.headers['x-admin-key'] || req.body?.currentKey;
  const newSecret = req.body?.newKey;

  if (!currentSecret || !providedCurrentKey || providedCurrentKey !== currentSecret) {
    res.status(403).json({ success: false, error: 'Forbidden: Invalid current administrative secret' });
    return;
  }

  if (!newSecret || typeof newSecret !== 'string' || isKnownInsecureSecret(newSecret) || newSecret.length < 16) {
    res.status(400).json({ success: false, error: 'Bad Request: New admin key must be at least 16 characters and secure' });
    return;
  }

  dynamicAdminSecret = newSecret.trim();
  res.json({
    success: true,
    message: 'Administrative secret rotated successfully',
    timestamp: new Date().toISOString(),
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
    audience: 'saral-domain-coordinators',
  });
});

export default router;
