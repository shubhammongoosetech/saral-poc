import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { KeyManager } from '../auth/token';
import { createAccountSession, InvalidAccountSession, revokeAccountSession } from '../auth/accountSession';
import { getGoogleClientId } from '../auth/google';
import { DataStore } from '../storage/store';
import {
  requestPhoneOtp,
  verifyPhoneOtp,
  verifyGoogleToken,
  linkAccount,
  PhoneAuthError,
} from '../services/accountService';
import {
  enrollTotp,
  MfaChallengeError,
  verifyMfaChallenge,
  decryptTotpSecret,
  computeTotpToken,
} from '../services/mfaService';
import { requireAuth, requireMfa } from '../middleware/authGuard';
import {
  getAdminSecret, isKnownInsecureSecret, isLocalAuthEnabled, matchesSecret, setDynamicAdminSecret,
} from '../config/auth';
import { env } from '../config/env';
import { ALL_WORKING_DAYS, InvalidWorkingPolicy, parseWorkingPolicy } from '../services/policyService';

const router = Router();
const keyManager = KeyManager.getInstance();
const store = DataStore.getInstance();

router.use((_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

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

  if (!isLocalAuthEnabled()) {
    if (!matchesSecret(providedKey, adminSecret)) {
      res.status(403).json({
        success: false,
        error: 'Forbidden: Development authentication is disabled. Authenticated administrative credentials required.',
      });
      return;
    }
  }

  if (requestedRole === 'admin') {
    if (!matchesSecret(providedKey, adminSecret)) {
      res.status(403).json({
        success: false,
        error: 'Forbidden: Admin role issuance requires authenticated administrative secret credentials.',
      });
      return;
    }
  }

  const validRoles = ['admin', 'operator', 'auditor', 'viewer'];
  if (typeof subject !== 'string' || !subject.trim() || subject.length > 128 || !validRoles.includes(requestedRole)) {
    res.status(400).json({ success: false, error: 'Invalid token subject or role' });
    return;
  }
  const role = requestedRole;

  const token = keyManager.issueToken(subject, role);

  res.json({
    success: true,
    token,
    tokenType: 'Bearer',
    expiresIn: 3600,
    subject,
    role,
    algorithm: 'EdDSA',
    kid: keyManager.activeKid,
    issuer: keyManager.issuer,
    audience: keyManager.audience,
  });
};

router.post('/auth/token', handleTokenIssuance);
router.post('/api/auth/token', handleTokenIssuance);

router.post('/auth/rotate-admin-key', (req: Request, res: Response) => {
  const currentSecret = getAdminSecret();
  const providedCurrentKey = req.headers['x-admin-key'] || req.body?.currentKey;
  const newSecret = typeof req.body?.newKey === 'string' ? req.body.newKey.trim() : '';

  if (!matchesSecret(providedCurrentKey, currentSecret)) {
    res.status(403).json({ success: false, error: 'Forbidden: Invalid current administrative secret' });
    return;
  }

  if (isKnownInsecureSecret(newSecret) || newSecret.length < 16) {
    res.status(400).json({ success: false, error: 'Bad Request: New admin key must be at least 16 characters and secure' });
    return;
  }

  setDynamicAdminSecret(newSecret);
  res.json({
    success: true,
    message: 'Administrative secret rotated successfully',
    timestamp: new Date().toISOString(),
  });
});

// Standard JWKS endpoints returning public Ed25519 verification keys
const handleJwks = (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=300');
  res.json(keyManager.getJwks());
};

router.get('/.well-known/jwks.json', handleJwks);
router.get('/api/.well-known/jwks.json', handleJwks);
router.get('/auth/jwks.json', handleJwks);
router.get('/api/auth/jwks.json', handleJwks);

router.get('/auth/public-key', (_req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/plain');
  res.send(keyManager.publicKeyPem);
});

router.get('/auth/public-key.json', (_req: Request, res: Response) => {
  res.json({
    publicKeyPem: keyManager.publicKeyPem,
    algorithm: 'EdDSA',
    kid: keyManager.activeKid,
    issuer: keyManager.issuer,
    audience: keyManager.audience,
    jwks: keyManager.getJwks(),
  });
});

// ─── USER ONBOARDING & AUTHENTICATION ENDPOINTS ─────────────────────────────

router.get('/auth/login-options', (_req, res) => {
  res.json({ googleClientId: getGoogleClientId(), developmentOtpEnabled: isLocalAuthEnabled() });
});

// POST /auth/google
router.post('/auth/google', async (req: Request, res: Response) => {
  try {
    const credential = req.body?.credential || req.body?.idToken;
    if (typeof credential !== 'string' || !credential) {
      res.status(400).json({ success: false, error: 'Missing Google credential or idToken' });
      return;
    }

    const result = await verifyGoogleToken(credential);
    res.json({
      success: true,
      ...result,
    });
  } catch {
    res.status(401).json({ success: false, error: 'Google authentication failed' });
  }
});

const googleCallbackUrl = process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3001/api/auth/google/callback';
const secureOAuthCookie = googleCallbackUrl.startsWith('https:');
const oauthCookieName = secureOAuthCookie ? '__Host-saral_google_oauth' : 'saral_google_oauth';
const oauthCookieOptions = { httpOnly: true, secure: secureOAuthCookie, sameSite: 'lax' as const, path: '/' };

router.get('/auth/google/url', (_req: Request, res: Response) => {
  const clientId = getGoogleClientId();
  if (!clientId) {
    res.status(503).json({ success: false, error: 'Google sign-in is unavailable' });
    return;
  }
  const state = crypto.randomBytes(32).toString('base64url');
  const nonce = crypto.randomBytes(32).toString('base64url');
  const verifier = crypto.randomBytes(32).toString('base64url');
  const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authUrl.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: googleCallbackUrl,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    nonce,
    code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
    code_challenge_method: 'S256',
  }).toString();
  res.set('Cache-Control', 'no-store');
  res.cookie(oauthCookieName, [state, nonce, verifier].join('.'), { ...oauthCookieOptions, maxAge: 300_000 });
  res.json({ success: true, authUrl: authUrl.href, state, clientIdConfigured: !!process.env.GOOGLE_CLIENT_ID });
});

const handleGoogleCallback = async (req: Request, res: Response) => {
  const cookie = req.headers.cookie?.split(';').map((entry) => entry.trim())
    .find((entry) => entry.startsWith(oauthCookieName + '='));
  const [state, nonce, verifier] = cookie?.slice(oauthCookieName.length + 1).split('.') ?? [];

  res.set('Cache-Control', 'no-store');
  res.set('Referrer-Policy', 'no-referrer');
  res.clearCookie(oauthCookieName, oauthCookieOptions);
  if (!state || !nonce || !verifier || !matchesSecret(req.query.state, state) || typeof req.query.code !== 'string') {
    res.status(400).json({ success: false, error: 'Invalid Google authorization callback' });
    return;
  }

  const clientId = getGoogleClientId();
  if (!clientId || !env.GOOGLE_CLIENT_SECRET) {
    res.status(503).json({ success: false, error: 'Google OAuth is unavailable' });
    return;
  }

  try {
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code: req.query.code,
        client_id: clientId,
        client_secret: env.GOOGLE_CLIENT_SECRET,
        redirect_uri: googleCallbackUrl,
        grant_type: 'authorization_code',
        code_verifier: verifier,
      }),
    });

    const tokenData = (await tokenRes.json()) as { id_token?: string };
    if (!tokenRes.ok || !tokenData.id_token) throw new Error('Google OAuth token exchange failed');

    const result = await verifyGoogleToken(tokenData.id_token, nonce);
    const redirect = new URL('/login', env.FRONTEND_URL);
    redirect.hash = new URLSearchParams({ token: result.token }).toString();
    res.redirect(303, redirect.href);
  } catch {
    res.status(401).json({ success: false, error: 'Google authentication failed' });
  }
};

router.get('/auth/google/callback', handleGoogleCallback);
router.get('/api/auth/google/callback', handleGoogleCallback);

// POST /auth/phone/request-otp & /auth/otp/request & /auth/otp/send
const handleRequestOtp = async (req: Request, res: Response) => {
  if (!isLocalAuthEnabled()) {
    res.status(503).json({ success: false, error: 'SMS code delivery is unavailable' });
    return;
  }
  try {
    const mobile = req.body?.mobile;
    if (!mobile || typeof mobile !== 'string') {
      res.status(400).json({ success: false, error: 'Valid mobile number required' });
      return;
    }

    const result = await requestPhoneOtp(mobile);
    res.json(result);
  } catch (err) {
    const status = err instanceof PhoneAuthError ? err.status : 503;
    const error = err instanceof PhoneAuthError ? err.message : 'Unable to dispatch verification code';
    res.status(status).json({ success: false, error });
  }
};

router.post('/auth/phone/request-otp', handleRequestOtp);
router.post('/auth/otp/request', handleRequestOtp);
router.post('/auth/otp/send', handleRequestOtp);

// POST /auth/phone/verify-otp & /auth/otp/verify
const handleVerifyOtp = async (req: Request, res: Response) => {
  if (!isLocalAuthEnabled()) {
    res.status(503).json({ success: false, error: 'SMS code delivery is unavailable' });
    return;
  }
  try {
    const mobile = req.body?.mobile;
    const otp = req.body?.otp || req.body?.code;
    if (typeof mobile !== 'string' || typeof otp !== 'string' || !/^\d{6}$/.test(otp.trim())) {
      res.status(400).json({ success: false, error: 'Mobile and 6-digit OTP code required' });
      return;
    }

    const result = await verifyPhoneOtp(mobile, otp);
    res.json({
      success: true,
      ...result,
    });
  } catch (err) {
    const status = err instanceof PhoneAuthError ? err.status : 401;
    const error = err instanceof PhoneAuthError ? err.message : 'Invalid or expired verification code';
    res.status(status).json({ success: false, error });
  }
};

router.post('/auth/phone/verify-otp', handleVerifyOtp);
router.post('/auth/otp/verify', handleVerifyOtp);

const handleMfaStatus = async (req: Request, res: Response) => {
  const mfa = await store.findPersistedMfa(req.user!.userId);
  const enrolled = !!(mfa?.totpSecretEncrypted && mfa.verifiedAt);
  res.json({ success: true, enrolled, type: mfa?.type || 'totp', verified: enrolled, developmentOtpEnabled: isLocalAuthEnabled() });
};

router.get('/mfa/status', requireAuth, handleMfaStatus);
router.get('/auth/mfa/status', requireAuth, handleMfaStatus);

const handleMfaEnroll = async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  if (store.getMfa(userId)?.verifiedAt) {
    res.status(409).json({ success: false, error: 'MFA is already enrolled' });
    return;
  }

  try {
    const user = store.findUserById(userId);
    const enrollment = await enrollTotp(userId, user?.email || user?.mobile || 'saral-user');
    const devOtp = isLocalAuthEnabled() ? computeTotpToken(enrollment.secret, Math.floor(Date.now() / 30_000)) : undefined;
    res.json({ success: true, ...enrollment, devOtp });
  } catch (err: unknown) {
    if (err instanceof Error && err.message.startsWith('MFA is already enrolled')) {
      res.status(409).json({ success: false, error: err.message });
      return;
    }
    res.status(500).json({ success: false, error: 'MFA enrollment failed' });
  }
};

router.post('/mfa/enroll', requireAuth, handleMfaEnroll);
router.post('/auth/mfa/enroll', requireAuth, handleMfaEnroll);

// TOTP is generated by the user's authenticator. Local development can display a code explicitly.
const handleMfaSend = async (req: Request, res: Response) => {
  const existingMfa = await store.findPersistedMfa(req.user!.userId);
  if (!existingMfa?.totpSecretEncrypted || !existingMfa.verifiedAt) {
    res.status(409).json({ success: false, error: 'MFA enrollment is required' });
    return;
  }

  try {
    let devOtp: string | undefined;
    if (isLocalAuthEnabled()) {
      const secret = decryptTotpSecret(existingMfa.totpSecretEncrypted);
      devOtp = computeTotpToken(secret, Math.floor(Date.now() / 30_000));
    }
    res.json({ success: true, message: 'Use your authenticator or a backup code', devOtp });
  } catch {
    res.status(500).json({ success: false, error: 'MFA challenge unavailable' });
  }
};

router.post('/mfa/send', requireAuth, handleMfaSend);
router.post('/auth/mfa/send', requireAuth, handleMfaSend);

const handleMfaVerifyEndpoint = async (req: Request, res: Response) => {
  const { userId, sessionId } = req.user!;
  const code = req.body?.otp || req.body?.code || req.body?.recoveryCode;
  if (typeof code !== 'string' || !code.trim() || code.length > 32) {
    res.status(400).json({ success: false, error: 'MFA code required' });
    return;
  }

  try {
    const [policy, wallet] = await Promise.all([store.loadPolicy(userId), store.loadWallet(userId)]);
    await verifyMfaChallenge(userId, code);
    const upgradedToken = await createAccountSession(userId, true, sessionId);

    res.json({
      success: true,
      token: upgradedToken,
      hasPolicy: !!policy,
      hasWallet: !!wallet && wallet.status === 'READY',
    });
  } catch (err: unknown) {
    if (err instanceof MfaChallengeError) {
      const code = err.rateLimited ? 'MFA_RATE_LIMITED' : 'MFA_CODE_INVALID';
      res.status(err.rateLimited ? 429 : 400).json({ success: false, code, error: err.message });
      return;
    }
    if (err instanceof InvalidAccountSession) {
      res.status(401).json({ success: false, error: 'Unauthorized: Invalid or expired token' });
      return;
    }
    res.status(503).json({ success: false, error: 'MFA verification is temporarily unavailable' });
  }
};

router.post('/mfa/verify', requireAuth, handleMfaVerifyEndpoint);
router.post('/auth/mfa/verify', requireAuth, handleMfaVerifyEndpoint);

// POST /auth/link-account (Requires Auth)
router.post('/auth/link-account', requireAuth, requireMfa, async (req: Request, res: Response) => {
  try {
    const userId = req.user!.userId;
    const { targetMethod, identifier } = req.body ?? {};
    if ((targetMethod !== 'google' && targetMethod !== 'mobile') || typeof identifier !== 'string' || !identifier) {
      res.status(400).json({ success: false, error: 'targetMethod and identifier are required' });
      return;
    }

    const result = await linkAccount(userId, targetMethod, identifier);
    res.json(result);
  } catch {
    res.status(400).json({ success: false, error: 'Unable to verify or link this identity' });
  }
});

// POST /auth/logout
router.post('/auth/logout', requireAuth, async (req: Request, res: Response) => {
  const { userId, sessionId } = req.user!;
  await revokeAccountSession(userId, sessionId);
  res.json({ success: true, message: 'Logged out successfully' });
});

// GET /auth/session & /auth/me (Validates active session)
const handleSession = async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const [user, mfa, policy, wallet] = await Promise.all([
    store.findPersistedUser({ id: userId }), store.findPersistedMfa(userId),
    store.loadPolicy(userId), store.loadWallet(userId),
  ]);

  res.json({
    success: true,
    user: user || { id: userId, loginMethod: 'unknown' },
    mfaEnrolled: !!mfa?.totpSecretEncrypted,
    mfaVerified: req.user!.mfaVerified,
    hasPolicy: !!policy,
    hasWallet: !!wallet && wallet.status === 'READY',
    policy: req.user!.mfaVerified ? policy : null,
  });
};

router.get('/auth/session', requireAuth, handleSession);
router.get('/auth/me', requireAuth, handleSession);

// GET /profile (Used by frontend profileApi)
router.get('/profile', requireAuth, requireMfa, async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const [user, mfa, policy, wallet] = await Promise.all([
    store.findPersistedUser({ id: userId }), store.findPersistedMfa(userId),
    store.loadPolicy(userId), store.loadWallet(userId),
  ]);

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
router.post('/profile/policy', requireAuth, requireMfa, async (req: Request, res: Response) => {
  try {
    const record = parseWorkingPolicy(req.user!.userId, req.body ?? {}, ALL_WORKING_DAYS);
    await store.savePolicy(record);
    res.json({
      message: 'Policy saved successfully',
      policy: {
        startTime: record.startTime,
        endTime: record.endTime,
        timezone: record.timezone,
        city: record.allowedRegion,
        lat: record.lat,
        lng: record.lng,
        radiusKm: record.radiusMeters! / 1000,
      },
    });
  } catch (err) {
    if (err instanceof InvalidWorkingPolicy) {
      res.status(400).json({ error: err.message });
      return;
    }
    res.status(503).json({ error: 'Unable to save working policy' });
  }
});

export default router;
