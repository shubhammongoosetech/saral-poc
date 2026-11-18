import { Router, Request, Response } from 'express';
import fs from 'fs';
import { KeyManager } from '../auth/token';
import { DataStore } from '../storage/store';
import {
  requestPhoneOtp,
  verifyPhoneOtp,
  verifyGoogleToken,
  linkAccount,
} from '../services/accountService';
import {
  enrollTotp,
  verifyMfaChallenge,
} from '../services/mfaService';
import { requireAuth } from '../middleware/authGuard';

const router = Router();
const keyManager = KeyManager.getInstance();
const store = DataStore.getInstance();

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
  const isLocalDevEnv =
    process.env.NODE_ENV === 'development' ||
    process.env.NODE_ENV === 'local' ||
    process.env.NODE_ENV === 'test' ||
    !process.env.NODE_ENV;
  const isDevAuthExplicitlyEnabled = process.env.ENABLE_DEV_AUTH === 'true' && isLocalDevEnv;
  const adminSecret = getAdminSecret();

  const subject = req.body?.subject || req.body?.username || 'dev-operator-1';
  const requestedRole = req.body?.role || 'operator';
  const providedKey = req.headers['x-admin-key'] || req.body?.adminSecret;

  if (providedKey && typeof providedKey === 'string' && isKnownInsecureSecret(providedKey)) {
    res.status(403).json({
      success: false,
      error: 'Forbidden: Insecure or default administrative credentials rejected.',
    });
    return;
  }

  if (!isDevAuthExplicitlyEnabled) {
    if (!adminSecret || !providedKey || providedKey !== adminSecret) {
      res.status(403).json({
        success: false,
        error: 'Forbidden: Development authentication is disabled. Authenticated administrative credentials required.',
      });
      return;
    }
  }

  if (requestedRole === 'admin') {
    if (!adminSecret || !providedKey || providedKey !== adminSecret) {
      res.status(403).json({
        success: false,
        error: 'Forbidden: Admin role issuance requires authenticated administrative secret credentials.',
      });
      return;
    }
  }

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

router.post('/auth/token', handleTokenIssuance);
router.post('/api/auth/token', handleTokenIssuance);

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

router.get('/auth/public-key', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/plain');
  res.send(keyManager.publicKeyPem);
});

router.get('/auth/public-key.json', (_req: Request, res: Response) => {
  res.json({
    publicKeyPem: keyManager.publicKeyPem,
    algorithm: 'RS256',
    issuer: 'saral-auth-server',
    audience: 'saral-domain-coordinators',
  });
});

// ─── USER ONBOARDING & AUTHENTICATION ENDPOINTS ─────────────────────────────

// POST /auth/google
router.post('/auth/google', (req: Request, res: Response) => {
  try {
    const credential = req.body?.credential || req.body?.idToken;
    if (!credential) {
      res.status(400).json({ success: false, error: 'Missing Google credential or idToken' });
      return;
    }

    const result = verifyGoogleToken(credential);
    res.json({
      success: true,
      ...result,
    });
  } catch (err: any) {
    res.status(401).json({ success: false, error: err.message || 'Google authentication failed' });
  }
});

// POST /auth/phone/request-otp
router.post('/auth/phone/request-otp', (req: Request, res: Response) => {
  try {
    const mobile = req.body?.mobile;
    if (!mobile || typeof mobile !== 'string') {
      res.status(400).json({ success: false, error: 'Valid mobile number required' });
      return;
    }

    const result = requestPhoneOtp(mobile);
    res.json(result);
  } catch (err: any) {
    res.status(429).json({ success: false, error: err.message || 'Failed to dispatch OTP' });
  }
});

// POST /auth/phone/verify-otp
router.post('/auth/phone/verify-otp', (req: Request, res: Response) => {
  try {
    const mobile = req.body?.mobile;
    const otp = req.body?.otp || req.body?.code;
    if (!mobile || !otp) {
      res.status(400).json({ success: false, error: 'Mobile and 6-digit OTP code required' });
      return;
    }

    const result = verifyPhoneOtp(mobile, otp);
    res.json({
      success: true,
      ...result,
    });
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message || 'OTP verification failed' });
  }
});

// POST /auth/link-account (Requires Auth)
router.post('/auth/link-account', requireAuth, (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId;
    const { targetMethod, identifier } = req.body;
    if (!targetMethod || !identifier) {
      res.status(400).json({ success: false, error: 'targetMethod and identifier are required' });
      return;
    }

    const result = linkAccount(userId, targetMethod, identifier);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ success: false, error: err.message || 'Account linking failed' });
  }
});

// POST /auth/mfa/enroll (Requires Auth)
router.post('/auth/mfa/enroll', requireAuth, (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId;
    const user = store.findUserById(userId);
    const identifier = user?.email || user?.mobile || userId;

    const result = enrollTotp(userId, identifier);
    res.json({
      success: true,
      ...result,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message || 'MFA enrollment failed' });
  }
});

// POST /auth/mfa/verify (Requires Auth)
router.post('/auth/mfa/verify', requireAuth, (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId;
    const code = req.body?.code || req.body?.recoveryCode;
    if (!code) {
      res.status(400).json({ success: false, error: 'MFA code or recovery code required' });
      return;
    }

    const result = verifyMfaChallenge(userId, code);
    // Issue upgraded token with mfaVerified: true
    const upgradedToken = keyManager.issueToken(userId, 'operator');

    const policy = store.getPolicy(userId);
    const wallet = store.getWalletByUserId(userId);

    res.json({
      success: true,
      token: upgradedToken,
      method: result.method,
      hasPolicy: !!policy,
      hasWallet: !!wallet && wallet.status === 'READY',
    });
  } catch (err: any) {
    res.status(401).json({ success: false, error: err.message || 'MFA verification failed' });
  }
});

// POST /auth/logout
router.post('/auth/logout', (_req: Request, res: Response) => {
  res.json({ success: true, message: 'Logged out successfully' });
});

// GET /auth/session (Validates active session)
router.get('/auth/session', requireAuth, (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const user = store.findUserById(userId);
  const mfa = store.getMfa(userId);
  const policy = store.getPolicy(userId);
  const wallet = store.getWalletByUserId(userId);

  res.json({
    success: true,
    user: user || { id: userId, loginMethod: 'unknown' },
    mfaEnrolled: !!mfa?.totpSecretEncrypted,
    mfaVerified: !!mfa?.verifiedAt,
    hasPolicy: !!policy,
    hasWallet: !!wallet && wallet.status === 'READY',
    policy: policy || null,
  });
});

export default router;
