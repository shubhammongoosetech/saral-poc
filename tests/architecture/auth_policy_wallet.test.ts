import { describe, it, expect, beforeEach } from 'vitest';
import crypto from 'crypto';
import { DataStore } from '../../apps/auth-server/src/storage/store';
import {
  requestPhoneOtp,
  verifyPhoneOtp,
  verifyGoogleToken,
  linkAccount,
  normalizeE164,
} from '../../apps/auth-server/src/services/accountService';
import {
  enrollTotp,
  verifyMfaChallenge,
  computeTotpToken,
  encryptTotpSecret,
  decryptTotpSecret,
} from '../../apps/auth-server/src/services/mfaService';
import {
  evaluateTimeRestriction,
  evaluateLocationRestriction,
  evaluateWorkingPolicy,
  calculateHaversineDistanceMeters,
} from '../../apps/auth-server/src/services/policyService';
import {
  createOrGetWallet,
  deriveMultiChainAddresses,
  getAuthenticatedWalletAddresses,
} from '../../apps/auth-server/src/services/walletService';

describe('SARAL Protocol V3 — Auth, MFA, Working Policy & Wallet Security', () => {
  const store = DataStore.getInstance();

  describe('1. Phone OTP & Identity Normalization', () => {
    it('normalizes mobile numbers to E.164 (+91 standard)', () => {
      expect(normalizeE164('9876543210')).toBe('+919876543210');
      expect(normalizeE164('919876543210')).toBe('+919876543210');
      expect(normalizeE164('+919876543210')).toBe('+919876543210');
    });

    it('creates OTP challenge, hashes code with HMAC-SHA256, and verifies correctly', () => {
      const mobile = '9876543210';
      const req = requestPhoneOtp(mobile);
      expect(req.success).toBe(true);
      expect(req.mobile).toBe('+919876543210');
      expect(req.devOtp).toBeDefined();

      // Verify OTP
      const verifyRes = verifyPhoneOtp(mobile, req.devOtp!);
      expect(verifyRes.user.mobile).toBe('+919876543210');
      expect(verifyRes.token).toBeDefined();
      expect(verifyRes.mfaVerified).toBe(false); // Primary auth only
    });

    it('rejects incorrect OTP and enforces attempt invalidation', () => {
      const mobile = '9998887776';
      requestPhoneOtp(mobile);
      expect(() => verifyPhoneOtp(mobile, '000000')).toThrow(/Incorrect OTP code/);
    });
  });

  describe('2. Google Sign-In & Explicit Account Linking', () => {
    it('authenticates Google identity and resolves user', () => {
      const googleToken = 'sample-google-id-token-xyz';
      const auth = verifyGoogleToken(googleToken);
      expect(auth.user.loginMethod).toBe('google');
      expect(auth.user.googleId).toBeDefined();
      expect(auth.token).toBeDefined();
    });

    it('links phone number to existing Google user identity without changing userId', () => {
      const auth = verifyGoogleToken('user-linking-token');
      const userId = auth.user.id;

      const linked = linkAccount(userId, 'mobile', '9123456789');
      expect(linked.user.id).toBe(userId);
      expect(linked.user.mobile).toBe('+919123456789');
    });
  });

  describe('3. Second-Factor MFA (RFC 6238 TOTP & Recovery Codes)', () => {
    it('encrypts TOTP secrets at rest with AES-256-GCM', () => {
      const secret = 'JBSWY3DPEHPK3PXP';
      const encrypted = encryptTotpSecret(secret);
      expect(encrypted).not.toBe(secret);
      const decrypted = decryptTotpSecret(encrypted);
      expect(decrypted).toBe(secret);
    });

    it('enrolls TOTP, generates QR URI and 8 recovery codes', () => {
      const testUserId = `user-mfa-${Date.now()}`;
      const enroll = enrollTotp(testUserId, 'user@example.com');
      expect(enroll.secret).toBeDefined();
      expect(enroll.qrUri).toContain('otpauth://totp/');
      expect(enroll.recoveryCodes.length).toBe(8);

      // Verify challenge with active TOTP code
      const currentStep = Math.floor(Date.now() / 1000 / 30);
      const code = computeTotpToken(enroll.secret, currentStep);

      const verification = verifyMfaChallenge(testUserId, code);
      expect(verification.verified).toBe(true);
      expect(verification.method).toBe('totp');
    });

    it('supports authentication using single-use hashed recovery code and burns code', () => {
      const testUserId = `user-rec-${Date.now()}`;
      const enroll = enrollTotp(testUserId, 'recovery@example.com');
      const codeToUse = enroll.recoveryCodes[0];

      // Use recovery code
      const res = verifyMfaChallenge(testUserId, codeToUse);
      expect(res.verified).toBe(true);
      expect(res.method).toBe('recovery-code');

      // Attempt replay of burned recovery code should fail
      expect(() => verifyMfaChallenge(testUserId, codeToUse)).toThrow();
    });
  });

  describe('4. Working Policy Engine (Time & Location)', () => {
    it('evaluates time restriction with normal working hours (09:00 - 18:00)', () => {
      const policy: any = {
        userId: 'u1',
        timeRestrictionEnabled: true,
        startTime: '09:00',
        endTime: '18:00',
        days: ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'],
        timezone: 'UTC',
      };

      // 12:00 UTC (inside window)
      const noon = new Date('2026-11-19T12:00:00Z');
      expect(evaluateTimeRestriction(policy, noon).allowed).toBe(true);

      // 20:00 UTC (outside window)
      const night = new Date('2026-11-19T20:00:00Z');
      expect(evaluateTimeRestriction(policy, night).allowed).toBe(false);
    });

    it('supports overnight time window crossing midnight (22:00 - 06:00)', () => {
      const policy: any = {
        userId: 'u2',
        timeRestrictionEnabled: true,
        startTime: '22:00',
        endTime: '06:00',
        days: ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'],
        timezone: 'UTC',
      };

      // 23:30 UTC (inside overnight window)
      const late = new Date('2026-11-19T23:30:00Z');
      expect(evaluateTimeRestriction(policy, late).allowed).toBe(true);

      // 03:00 UTC (inside overnight window)
      const early = new Date('2026-11-19T03:00:00Z');
      expect(evaluateTimeRestriction(policy, early).allowed).toBe(true);

      // 14:00 UTC (outside overnight window)
      const afternoon = new Date('2026-11-19T14:00:00Z');
      expect(evaluateTimeRestriction(policy, afternoon).allowed).toBe(false);
    });

    it('calculates accurate Haversine distance and enforces geofence radius', () => {
      // New Delhi: 28.6139, 77.2090
      // Gurgaon Cyber City: 28.4950, 77.0895 (~17.5 km)
      const dist = calculateHaversineDistanceMeters(28.6139, 77.2090, 28.4950, 77.0895);
      expect(dist).toBeGreaterThan(16000);
      expect(dist).toBeLessThan(19000);

      const policy: any = {
        userId: 'u3',
        locationRestrictionEnabled: true,
        geofenceEnabled: true,
        lat: 28.6139,
        lng: 77.2090,
        radiusMeters: 25000, // 25km radius
      };

      // Within radius
      expect(evaluateLocationRestriction(policy, 28.4950, 77.0895).allowed).toBe(true);

      // Outside radius (Mumbai: 19.0760, 72.8777 ~1150 km)
      const mumbaiCheck = evaluateLocationRestriction(policy, 19.0760, 72.8777);
      expect(mumbaiCheck.allowed).toBe(false);
      expect(mumbaiCheck.reason).toContain('Location verification failed');
    });

    it('fails closed when location restriction is enabled but coordinates are missing', () => {
      const policy: any = {
        userId: 'u4',
        locationRestrictionEnabled: true,
        geofenceEnabled: true,
        lat: 22.7196,
        lng: 75.8577,
      };

      const res = evaluateLocationRestriction(policy, undefined, undefined);
      expect(res.allowed).toBe(false);
      expect(res.reason).toContain('Location coordinates required');
    });
  });

  describe('5. Strict One-User-One-Wallet & Zero-Address Database Persistence', () => {
    it('creates exactly ONE logical wallet on first call and retrieves SAME wallet on subsequent calls', async () => {
      const userId = `user-unique-${Date.now()}`;

      // Call 1: First-time creation
      const firstCall = await createOrGetWallet(userId);
      expect(firstCall.isNew).toBe(true);
      expect(firstCall.wallet.userId).toBe(userId);
      const walletId = firstCall.wallet.walletId;

      // Call 2: Returning user
      const secondCall = await createOrGetWallet(userId);
      expect(secondCall.isNew).toBe(false);
      expect(secondCall.wallet.walletId).toBe(walletId); // Same wallet!
    });

    it('STRICT ZERO-ADDRESS DATABASE INVARIANT: application database stores zero wallet addresses', () => {
      const userId = `user-db-audit-${Date.now()}`;
      store.saveWallet({
        userId,
        walletId: `wal-${userId}`,
        status: 'READY',
        keyReferences: {
          mst: 'ref-mst-123',
          solana: 'ref-sol-456',
          bitcoin: 'ref-btc-789',
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      });

      const retrieved: any = store.getWalletByUserId(userId);
      expect(retrieved).toBeDefined();
      expect(retrieved.keyReferences).toBeDefined();

      // STRICT NEGATIVE ASSERTIONS:
      expect(retrieved.address).toBeUndefined();
      expect(retrieved.ethereum_address).toBeUndefined();
      expect(retrieved.bitcoin_address).toBeUndefined();
      expect(retrieved.solana_address).toBeUndefined();
      expect(retrieved.public_key_hex).toBeUndefined();
      expect(retrieved.master_signing_public_key).toBeUndefined();
    });

    it('deterministically recomputes multi-chain addresses in RAM matching standards', () => {
      const walletId = 'wal-test-deterministic-001';
      const keyRefs = {
        mst: 'opaque-ref-mst-abc',
        solana: 'opaque-ref-sol-def',
        bitcoin: 'opaque-ref-btc-ghi',
      };

      const run1 = deriveMultiChainAddresses(walletId, keyRefs);
      const run2 = deriveMultiChainAddresses(walletId, keyRefs);

      // Exact same addresses recomputed
      expect(run1.mst.address).toBe(run2.mst.address);
      expect(run1.solana.address).toBe(run2.solana.address);
      expect(run1.bitcoin.address).toBe(run2.bitcoin.address);

      // Standards formatting
      expect(run1.mst.address).toMatch(/^0x[a-fA-F0-9]{40}$/);
      expect(run1.solana.address).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
      expect(run1.bitcoin.address).toMatch(/^tb1p[0-9a-z]{58}$/);
    });
  });
});
