import { Request, Response } from 'express';
import fs from 'fs';
import crypto from 'crypto';
import { KeyManager } from '../auth/token';
import { DataStore } from '../storage/store';
import {
  requestPhoneOtp,
  verifyPhoneOtp,
  verifyGoogleToken,
  linkAccount as linkAccountService,
} from '../services/accountService';
import { MfaController } from './mfa.controller';
import { PolicyController } from './policy.controller';

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

export function getAdminSecret(): string | null {
  if (dynamicAdminSecret) {
    return dynamicAdminSecret;
  }

  // 1. Check Docker secret file
  const secretPath = process.env.SARAL_ADMIN_KEY_FILE || '/run/secrets/saral_admin_key';
  try {
    if (fs.existsSync(secretPath)) {
      const content = fs.readFileSync(secretPath, 'utf8').trim();
      if (content && !isKnownInsecureSecret(content)) {
        dynamicAdminSecret = content;
        return content;
      }
    }
  } catch (_) { }

  // 2. Check Environment variable
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

/**
 * AuthController
 * Feature: Identity & Authentication Management
 * 
 * Handles:
 * - Health check & server status
 * - RS256 Admin & Operator JWT token issuance
 * - Dynamic Admin Key rotation
 * - RSA Public Key discovery (PEM & JSON)
 * - Google OAuth 2.0 flow & credential verification
 * - E.164 Phone OTP requests and timing-safe verification
 * - User session retrieval, logout, and multi-login account linking
 */
export class AuthController {
  // ─── HEALTH CHECK ─────────────────────────────────────────────────────────

  public static healthCheck(_req: Request, res: Response): void {
    res.json({
      status: 'ok',
      service: 'saral-auth-server',
      version: '3.0.0',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
    });
  }

  // ─── ADMIN & OPERATOR TOKEN ISSUANCE ─────────────────────────────────────

  /**
   * POST /auth/token & POST /api/auth/token
   * Hinglish: Operator ya Admin ke liye RS256 JWT tokens issue karta hai.
   */
  public static issueToken(req: Request, res: Response): void {
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
  }

  // ─── ADMIN KEY ROTATION ──────────────────────────────────────────────────

  /**
   * POST /auth/rotate-admin-key
   * Hinglish: Purani admin key verify karke dynamically nayi key set karta hai.
   */
  public static rotateAdminKey(req: Request, res: Response): void {
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
  }

  // ─── PUBLIC KEYS DISCOVERY ────────────────────────────────────────────────

  /**
   * GET /auth/public-key
   * Hinglish: Coordinator aur verifier nodes ke liye RSA Public Key (PEM format) return karta hai.
   */
  public static getPublicKeyPem(_req: Request, res: Response): void {
    res.setHeader('Content-Type', 'text/plain');
    res.send(keyManager.publicKeyPem);
  }

  /**
   * GET /auth/public-key.json
   * Ed25519 Public Key metadata (algorithm, issuer) with JWKS in JSON.
   */
  public static getPublicKeyJson(_req: Request, res: Response): void {
    res.json({
      publicKeyPem: keyManager.publicKeyPem,
      algorithm: 'EdDSA',
      issuer: 'saral-auth-server',
      audience: 'saral-domain-coordinators',
      jwks: keyManager.getJwks(),
    });
  }

  /**
   * GET /.well-known/jwks.json
   * Public JWKS key set for JWT verification by Go coordinators and verifiers.
   */
  public static getJwks(_req: Request, res: Response): void {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'public, max-age=3600');
    res.json(keyManager.getJwks());
  }

  // ─── GOOGLE OAUTH AUTHENTICATION ──────────────────────────────────────────

  /**
   * POST /auth/google
   * Hinglish: Google ID token verify karke user login karta hai aur JWT token deta hai.
   */
  public static loginWithGoogle(req: Request, res: Response): void {
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
  }

  /**
   * GET /auth/google/url
   * Hinglish: Google Sign-in page ka URL banakar bhejta hai.
   */
  public static getGoogleAuthUrl(_req: Request, res: Response): void {
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
  }

  /**
   * GET /auth/google/callback & GET /api/auth/google/callback
   * Hinglish: Google OAuth callback handle karke authorization code ko token me badalta hai.
   */
  public static async handleGoogleCallback(req: Request, res: Response): Promise<void> {
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
      res.status(503).json({
        success: false,
        error: 'Google OAuth configuration missing: GOOGLE_CLIENT_SECRET is not configured on auth-server.',
        codeReceived: true,
      });
      return;
    }

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
  }

  // ─── PHONE OTP AUTHENTICATION ─────────────────────────────────────────────

  /**
   * POST /auth/phone/request-otp & POST /auth/otp/request
   * Hinglish: User ke mobile number par 6-digit login OTP dispatch karta hai.
   */
  public static requestOtp(req: Request, res: Response): void {
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
  }

  /**
   * POST /auth/phone/verify-otp & POST /auth/otp/verify
   * Hinglish: 6-digit OTP verify karke preliminary JWT token deta hai.
   */
  public static verifyOtp(req: Request, res: Response): void {
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
  }

  // ─── AUTHENTICATED USER SESSIONS & PROFILE ────────────────────────────────

  /**
   * POST /auth/link-account
   * Hinglish: Maujooda account me naya login method (jaise phone) link karta hai bina userId badle.
   */
  public static linkAccount(req: Request, res: Response): void {
    try {
      const userId = req.user!.userId;
      const { targetMethod, identifier } = req.body;
      if (!targetMethod || !identifier) {
        res.status(400).json({ success: false, error: 'targetMethod and identifier are required' });
        return;
      }

      const result = linkAccountService(userId, targetMethod, identifier);
      res.json(result);
    } catch (err: any) {
      res.status(400).json({ success: false, error: err.message || 'Account linking failed' });
    }
  }

  /**
   * POST /auth/logout
   * Hinglish: Session logout acknowledge karta hai.
   */
  public static logout(_req: Request, res: Response): void {
    res.json({ success: true, message: 'Logged out successfully' });
  }

  /**
   * GET /auth/session & GET /auth/me
   * Hinglish: Current session ka gate status (MFA status, Policy status, Wallet status) deta hai.
   */
  public static getSession(req: Request, res: Response): void {
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
  }

  // ─── BACKWARD COMPATIBILITY DELEGATES ────────────────────────────────────
  public static getMfaStatus = MfaController.getStatus;
  public static enrollMfa = MfaController.enroll;
  public static sendMfaOtp = MfaController.sendOtp;
  public static verifyMfa = MfaController.verify;
  public static getProfile = PolicyController.getProfile;
  public static savePolicy = PolicyController.savePolicy;
}
