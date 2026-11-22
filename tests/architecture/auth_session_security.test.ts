import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAccountSession, revokeAccountSession, validateAccountSession } from '../../apps/auth-server/src/auth/accountSession';
import { KeyManager } from '../../apps/auth-server/src/auth/token';
import { verifyGoogleIdentity } from '../../apps/auth-server/src/auth/google';
import { env } from '../../apps/auth-server/src/config/env';
import { prisma } from '../../apps/auth-server/src/database/prisma';
import { DataStore } from '../../apps/auth-server/src/storage/store';
import { verifyGoogleToken } from '../../apps/auth-server/src/services/accountService';
import { computeTotpToken, encryptTotpSecret, enrollTotp, verifyMfaChallenge } from '../../apps/auth-server/src/services/mfaService';

vi.mock('../../apps/auth-server/src/database/prisma', () => ({
  prisma: {
    authSession: { create: vi.fn(), findUnique: vi.fn(), updateMany: vi.fn() },
    $transaction: vi.fn(),
  },
}));

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe('Google sign-in and browser session boundaries', () => {
  it('validates Google credentials and resolves the same durable identity on return', async () => {
    const signingKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const keyid = 'test-google-key';
    const jwk = signingKey.publicKey.export({ format: 'jwk' });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json({
      keys: [{ ...jwk, kid: keyid, alg: 'RS256' }],
    }, { headers: { 'Cache-Control': 'public, max-age=300' } })));

    const claims = { sub: 'google-account-123', email: 'person@example.test', email_verified: true, nonce: 'login-nonce' };
    const idToken = jwt.sign(claims, signingKey.privateKey, {
      algorithm: 'RS256', keyid, issuer: 'https://accounts.google.com', audience: env.GOOGLE_CLIENT_ID, expiresIn: '5m',
    });

    await expect(verifyGoogleIdentity(idToken, 'wrong-nonce')).rejects.toThrow('Invalid Google credential');
    const wrongAudience = jwt.sign(claims, signingKey.privateKey, {
      algorithm: 'RS256', keyid, issuer: 'https://accounts.google.com', audience: 'a-different-app', expiresIn: '5m',
    });
    await expect(verifyGoogleIdentity(wrongAudience)).rejects.toThrow('Invalid Google credential');
    const unsigned = jwt.sign(claims, null, { algorithm: 'none' });
    await expect(verifyGoogleIdentity(unsigned)).rejects.toThrow('Invalid Google credential');

    const store = DataStore.getInstance();
    const find = vi.spyOn(store, 'findPersistedUser');
    const save = vi.spyOn(store, 'saveUser').mockResolvedValue(undefined);
    vi.spyOn(store, 'findPersistedMfa').mockResolvedValue(null);
    vi.spyOn(store, 'loadPolicy').mockResolvedValue(null);
    vi.spyOn(store, 'loadWallet').mockResolvedValue(null);
    vi.spyOn(store, 'logSecurity').mockImplementation(() => {});
    find.mockResolvedValueOnce(null).mockResolvedValueOnce(null);
    const firstLogin = await verifyGoogleToken(idToken, claims.nonce);
    find.mockResolvedValueOnce(firstLogin.user);
    const secondLogin = await verifyGoogleToken(idToken, claims.nonce);

    expect(firstLogin.user.googleId).toBe(claims.sub);
    expect(secondLogin.user.id).toBe(firstLogin.user.id);
    expect(save).toHaveBeenCalledTimes(1);
    expect(KeyManager.getInstance().verifyAccountToken(secondLogin.token).mfaVerified).toBe(false);
  });

  it('rejects unused, revoked, and mesh-audience tokens at the account boundary', async () => {
    const keyManager = KeyManager.getInstance();
    const userId = crypto.randomUUID();
    const token = await createAccountSession(userId, true);
    const claims = keyManager.verifyAccountToken(token);
    const find = vi.mocked(prisma.authSession.findUnique);
    const session = {
      userId, revoked: false, mfaVerified: true, expiresAt: new Date(claims.exp * 1000),
      id: crypto.randomUUID(), tokenJti: claims.nonce!, createdAt: new Date(), ipAddress: null, userAgent: null,
    };
    find.mockResolvedValueOnce(session).mockResolvedValueOnce({ ...session, revoked: true }).mockResolvedValueOnce(null);

    await expect(validateAccountSession(token)).resolves.toMatchObject({ sub: userId, mfaVerified: true });
    await revokeAccountSession(userId, claims.nonce!);
    expect(prisma.authSession.updateMany).toHaveBeenCalledWith({
      where: { userId, tokenJti: claims.nonce }, data: { revoked: true },
    });
    await expect(validateAccountSession(token)).rejects.toThrow('Invalid account session');
    await expect(validateAccountSession(keyManager.issueAccountToken(userId, true))).rejects.toThrow('Invalid account session');
    await expect(validateAccountSession(keyManager.issueToken(userId, 'operator', true))).rejects.toThrow('Invalid account session');
  });

  it('consumes a primary account session when issuing an MFA-verified session', async () => {
    const userId = crypto.randomUUID();
    const primary = await createAccountSession(userId, false);
    const sessionId = KeyManager.getInstance().verifyAccountToken(primary).nonce;
    const tx = { authSession: { create: vi.fn(), updateMany: vi.fn() } };
    vi.mocked(prisma.$transaction).mockImplementation(async (operation: any) => operation(tx));
    tx.authSession.updateMany.mockResolvedValueOnce({ count: 1 }).mockResolvedValueOnce({ count: 0 });

    const upgraded = await createAccountSession(userId, true, sessionId);
    expect(KeyManager.getInstance().verifyAccountToken(upgraded).mfaVerified).toBe(true);
    expect(tx.authSession.updateMany).toHaveBeenCalledWith({
      where: { userId, tokenJti: sessionId, revoked: false, expiresAt: { gt: expect.any(Date) } },
      data: { revoked: true },
    });
    await expect(createAccountSession(userId, true, sessionId)).rejects.toThrow('Invalid account session');
    expect(tx.authSession.create).toHaveBeenCalledTimes(1);
  });

  it('uses persisted MFA state to reject a reused TOTP and a factor reset', async () => {
    const store = DataStore.getInstance();
    const now = Date.now();
    const step = Math.floor(now / 30_000);
    const secret = 'JBSWY3DPEHPK3PXP';
    const userId = crypto.randomUUID();
    const pending = {
      userId, type: 'totp' as const, totpSecretEncrypted: encryptTotpSecret(secret),
      updatedAt: new Date().toISOString(), recoveryCodesHashed: [],
    };
    const verifiedAt = new Date(step * 30_000);
    vi.spyOn(store, 'findPersistedMfa').mockResolvedValueOnce(pending)
      .mockResolvedValue({ ...pending, verifiedAt: verifiedAt.toISOString() });
    const saveVerifiedMfa = vi.spyOn(store, 'saveVerifiedMfa').mockResolvedValue(true);
    vi.spyOn(store, 'logSecurity').mockImplementation(() => {});

    const code = computeTotpToken(secret, step);
    await expect(verifyMfaChallenge(userId, code)).resolves.toMatchObject({ verified: true, method: 'totp' });
    expect(saveVerifiedMfa).toHaveBeenCalledWith(pending, verifiedAt, []);
    await expect(verifyMfaChallenge(userId, code)).rejects.toThrow('already used');
    await expect(enrollTotp(userId, 'account@example.test')).rejects.toThrow('already enrolled');
    expect(saveVerifiedMfa).toHaveBeenCalledTimes(1);
  });
});
