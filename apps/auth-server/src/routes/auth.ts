import { Router, Request, Response } from 'express';
import fs from 'fs';
import crypto from 'crypto';
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
  decryptTotpSecret,
  computeTotpToken,
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
const handleHealth = (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    service: 'saral-auth-server',
    version: '3.0.0',
    uptime: process.uptime(),
    timestamp: new Date().toISOString(),
  });
};

router.get('/health', handleHealth);
router.get('/auth/health', handleHealth);

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

// GET /auth/google/url
router.get('/auth/google/url', (_req: Request, res: Response) => {
  const clientId = process.env.GOOGLE_CLIENT_ID || '558208753253-gr5lji587t11l5m63d5udea4msbvbcds.apps.googleusercontent.com';
  const callbackUrl = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3001/api/auth/google/callback';
  const state = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(
    clientId
  )}&redirect_uri=${encodeURIComponent(
    callbackUrl
  )}&response_type=code&scope=openid%20email%20profile&state=${state}&nonce=${nonce}`;

  res.json({
    success: true,
    authUrl,
    state,
    clientIdConfigured: !!process.env.GOOGLE_CLIENT_ID,
  });
});

// GET /api/auth/google/callback and /auth/google/callback
const handleGoogleCallback = async (req: Request, res: Response) => {
  const code = req.query.code as string;
  const error = req.query.error as string;

  if (error) {
    res.redirect(`http://localhost:3000/?error=${encodeURIComponent(error)}`);
    return;
  }

  if (!code) {
    res.status(400).json({ success: false, error: 'Authorization code missing in Google callback' });
    return;
  }

  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientSecret) {
    // Report missing configuration explicitly
    res.status(503).json({
      success: false,
      error: 'Google OAuth configuration missing: GOOGLE_CLIENT_SECRET is not configured on auth-server.',
      codeReceived: true,
    });
    return;
  }

  // If secret configured, exchange code for tokens
  try {
    const clientId = process.env.GOOGLE_CLIENT_ID || '558208753253-gr5lji587t11l5m63d5udea4msbvbcds.apps.googleusercontent.com';
    const callbackUrl = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3001/api/auth/google/callback';
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: callbackUrl,
        grant_type: 'authorization_code',
      }),
    });
    const tokenData = (await tokenRes.json()) as any;
    if (!tokenRes.ok || !tokenData.id_token) {
      throw new Error(tokenData.error_description || 'Failed to exchange authorization code');
    }
    const result = verifyGoogleToken(tokenData.id_token);
    res.redirect(`http://localhost:3000/?token=${encodeURIComponent(result.token)}`);
  } catch (err: any) {
    res.redirect(`http://localhost:3000/?error=${encodeURIComponent(err.message)}`);
  }
};

router.get('/auth/google/callback', handleGoogleCallback);
router.get('/api/auth/google/callback', handleGoogleCallback);

// POST /auth/phone/request-otp & /auth/otp/request & /auth/otp/send
const handleRequestOtp = (req: Request, res: Response) => {
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
};

router.post('/auth/phone/request-otp', handleRequestOtp);
router.post('/auth/otp/request', handleRequestOtp);
router.post('/auth/otp/send', handleRequestOtp);

// POST /auth/phone/verify-otp & /auth/otp/verify
const handleVerifyOtp = (req: Request, res: Response) => {
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
};

router.post('/auth/phone/verify-otp', handleVerifyOtp);
router.post('/auth/otp/verify', handleVerifyOtp);

// GET /mfa/status & /auth/mfa/status
const handleMfaStatus = (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.status(401).json({ success: false, error: 'Authorization token required' });
      return;
    }
    const token = authHeader.replace(/^Bearer\s+/i, '');
    const decoded = keyManager.verifyToken(token);
    const userId = decoded.sub;
    const mfa = store.getMfa(userId);

    const enrolled = !!(mfa && mfa.totpSecretEncrypted && mfa.verifiedAt);
    res.json({
      success: true,
      enrolled,
      type: mfa?.type || 'totp',
      verified: !!mfa?.verifiedAt,
    });
  } catch (err: any) {
    res.status(401).json({ success: false, error: err.message || 'Unauthorized' });
  }
};

router.get('/mfa/status', handleMfaStatus);
router.get('/auth/mfa/status', handleMfaStatus);

// POST /mfa/enroll & /auth/mfa/enroll (Initial TOTP enrollment for new users)
const handleMfaEnroll = (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.status(401).json({ success: false, error: 'Authorization token required' });
      return;
    }
    const token = authHeader.replace(/^Bearer\s+/i, '');
    const decoded = keyManager.verifyToken(token);
    const userId = decoded.sub;
    const user = store.findUserById(userId);

    const emailOrPhone = user?.email || user?.mobile || 'saral-user';
    const enrollment = enrollTotp(userId, emailOrPhone);

    const isDev =
      process.env.ENABLE_DEV_AUTH === 'true' ||
      process.env.NODE_ENV === 'development' ||
      process.env.NODE_ENV === 'test' ||
      !process.env.NODE_ENV ||
      process.env.AUTH_DEV_OTP_DISPLAY === 'true';

    const currentStep = Math.floor(Date.now() / 1000 / 30);
    const devOtp = isDev ? computeTotpToken(enrollment.secret, currentStep) : undefined;

    res.json({
      success: true,
      secret: enrollment.secret,
      qrUri: enrollment.qrUri,
      recoveryCodes: enrollment.recoveryCodes,
      devOtp,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message || 'MFA enrollment failed' });
  }
};

router.post('/mfa/enroll', handleMfaEnroll);
router.post('/auth/mfa/enroll', handleMfaEnroll);

// POST /mfa/send & /auth/mfa/send (MFA OTP dispatch for returning / phone users)
const handleMfaSend = (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.status(401).json({ success: false, error: 'Authorization token required' });
      return;
    }
    const token = authHeader.replace(/^Bearer\s+/i, '');
    const decoded = keyManager.verifyToken(token);
    const userId = decoded.sub;
    const user = store.findUserById(userId);

    const mfaOtpCode = crypto.randomInt(100000, 1000000).toString();
    const codeHash = crypto.createHmac('sha256', 'mfa-salt').update(`${userId}:mfa:${mfaOtpCode}`).digest('hex');

    store.saveOtp({
      id: crypto.randomUUID(),
      userId,
      mobile: user?.mobile || 'mfa-totp',
      codeHash,
      purpose: 'mfa',
      expiresAt: Date.now() + 10 * 60 * 1000,
      used: false,
      attempts: 0,
      createdAt: Date.now(),
    });

    const isDev =
      process.env.ENABLE_DEV_AUTH === 'true' ||
      process.env.NODE_ENV === 'development' ||
      process.env.NODE_ENV === 'test' ||
      !process.env.NODE_ENV ||
      process.env.AUTH_DEV_OTP_DISPLAY === 'true';

    let devOtp: string | undefined = undefined;
    if (isDev) {
      const existingMfa = store.getMfa(userId);
      if (existingMfa?.totpSecretEncrypted) {
        try {
          const secret = decryptTotpSecret(existingMfa.totpSecretEncrypted);
          const currentStep = Math.floor(Date.now() / 1000 / 30);
          devOtp = computeTotpToken(secret, currentStep);
        } catch (_) {}
      }
      if (!devOtp) {
        devOtp = mfaOtpCode;
      }
    }

    console.log(`[MFA SEND] User ${userId} OTP: ${devOtp || mfaOtpCode}`);

    res.json({
      success: true,
      message: 'MFA challenge initiated',
      devOtp,
    });
  } catch (err: any) {
    res.status(401).json({ success: false, error: err.message || 'Failed to dispatch MFA code' });
  }
};

router.post('/mfa/send', handleMfaSend);
router.post('/auth/mfa/send', handleMfaSend);

// POST /mfa/verify
const handleMfaVerifyEndpoint = (req: Request, res: Response) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.status(401).json({ success: false, error: 'Authorization token required' });
      return;
    }
    const token = authHeader.replace(/^Bearer\s+/i, '');
    const decoded = keyManager.verifyToken(token);
    const userId = decoded.sub;

    const code = req.body?.otp || req.body?.code || req.body?.recoveryCode;
    if (!code) {
      res.status(400).json({ success: false, error: 'MFA code required' });
      return;
    }

    // First check if matching mfa OTP in store
    const activeMfaOtp = store.getActiveOtp(userId, 'mfa');
    let verified = false;
    if (activeMfaOtp) {
      const computedHash = crypto.createHmac('sha256', 'mfa-salt').update(`${userId}:mfa:${code.trim()}`).digest('hex');
      if (crypto.timingSafeEqual(Buffer.from(computedHash), Buffer.from(activeMfaOtp.codeHash))) {
        store.markOtpUsed(activeMfaOtp.id);
        verified = true;
      }
    }

    if (!verified) {
      // Check TOTP / recovery code challenge
      verifyMfaChallenge(userId, code);
      verified = true;
    }

    // Issue upgraded token with mfaVerified: true
    const upgradedToken = keyManager.issueToken(userId, 'operator', true);
    const policy = store.getPolicy(userId);
    const wallet = store.getWalletByUserId(userId);

    // Save MFA verified
    const existingMfa = store.getMfa(userId);
    store.saveMfa({
      userId,
      type: existingMfa?.type || 'totp',
      totpSecretEncrypted: existingMfa?.totpSecretEncrypted,
      recoveryCodesHashed: existingMfa?.recoveryCodesHashed,
      verifiedAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    res.json({
      success: true,
      token: upgradedToken,
      hasPolicy: !!policy,
      hasWallet: !!wallet && wallet.status === 'READY',
    });
  } catch (err: any) {
    res.status(401).json({ success: false, error: err.message || 'MFA verification failed' });
  }
};

router.post('/mfa/verify', handleMfaVerifyEndpoint);
router.post('/auth/mfa/verify', handleMfaVerifyEndpoint);

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

// GET /auth/session & /auth/me (Validates active session)
const handleSession = (req: Request, res: Response) => {
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
};

router.get('/auth/session', requireAuth, handleSession);
router.get('/auth/me', requireAuth, handleSession);

// GET /profile (Used by frontend profileApi)
router.get('/profile', requireAuth, (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const user = store.findUserById(userId);
  const mfa = store.getMfa(userId);
  const policy = store.getPolicy(userId);
  const wallet = store.getWalletByUserId(userId);

  res.json({
    user: user || { id: userId, login_method: 'mobile', created_at: new Date().toISOString() },
    hasPolicy: !!policy,
    policy: policy
      ? {
          startTime: policy.startTime,
          endTime: policy.endTime,
          start_time: policy.startTime,
          end_time: policy.endTime,
          timezone: policy.timezone,
          city: policy.allowedRegion,
          lat: policy.lat,
          lng: policy.lng,
          radiusKm: policy.radiusMeters ? policy.radiusMeters / 1000 : 25,
          radius_km: policy.radiusMeters ? policy.radiusMeters / 1000 : 25,
          setAt: policy.updatedAt,
          set_at: policy.updatedAt,
        }
      : null,
    hasWallet: !!wallet && wallet.status === 'READY',
    mfaVerified: !!mfa?.verifiedAt,
    mfa: mfa ? { type: mfa.type, verifiedAt: mfa.verifiedAt, verified_at: mfa.verifiedAt } : null,
  });
});

// POST /profile/policy (Used by frontend profileApi)
router.post('/profile/policy', requireAuth, (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId;
    const {
      startTime,
      endTime,
      timezone,
      city,
      lat,
      lng,
      radiusKm,
      timeRestrictionEnabled,
      locationRestrictionEnabled,
    } = req.body;

    const record = {
      userId,
      timeRestrictionEnabled: timeRestrictionEnabled !== undefined ? Boolean(timeRestrictionEnabled) : true,
      startTime: startTime || '09:00',
      endTime: endTime || '18:00',
      days: ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'],
      timezone: timezone || 'Asia/Kolkata',
      locationRestrictionEnabled: Boolean(locationRestrictionEnabled),
      allowedRegion: city || 'Indore',
      geofenceEnabled: Boolean(locationRestrictionEnabled),
      lat: lat !== undefined ? Number(lat) : 22.7196,
      lng: lng !== undefined ? Number(lng) : 75.8577,
      radiusMeters: (Number(radiusKm) || 25) * 1000,
      updatedAt: new Date().toISOString(),
    };

    store.savePolicy(record);

    res.json({
      message: 'Policy saved successfully',
      policy: {
        startTime: record.startTime,
        endTime: record.endTime,
        timezone: record.timezone,
        city: record.allowedRegion,
        lat: record.lat,
        lng: record.lng,
        radiusKm: Number(radiusKm) || 25,
      },
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Failed to save policy' });
  }
});

export default router;
