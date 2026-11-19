import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { prisma, connectPrisma, disconnectPrisma } from '../../apps/auth-server/src/database/prisma';
import { authRepository } from '../../apps/auth-server/src/modules/auth/auth.repository';
import { authService } from '../../apps/auth-server/src/modules/auth/auth.service';
import { mfaService } from '../../apps/auth-server/src/modules/mfa/mfa.service';
import { policyService } from '../../apps/auth-server/src/modules/policy/policy.service';
import { walletService } from '../../apps/auth-server/src/modules/wallet/wallet.service';
import { encryptTotpSecret, decryptTotpSecret } from '../../apps/auth-server/src/utils/crypto';

describe('SARAL Protocol — Prisma ORM & Database Layer Integration', () => {
  beforeAll(async () => {
    await connectPrisma();
  });

  afterAll(async () => {
    await disconnectPrisma();
  });

  it('1. Successfully connects to PostgreSQL database via Prisma', async () => {
    const result = await prisma.$queryRaw<Array<{ now: Date }>>`SELECT NOW() as now`;
    expect(result).toBeDefined();
    expect(result.length).toBe(1);
    expect(result[0].now).toBeInstanceOf(Date);
  });

  it('2. Reads existing pre-seeded users and wallet identities without schema loss', async () => {
    const operatorId = 'b79f86f3-44a6-48f9-be43-a1abb6456172';
    const user = await prisma.user.findUnique({
      where: { id: operatorId },
      include: {
        wallet: true,
        workPolicy: true,
      },
    });

    expect(user).toBeDefined();
    expect(user?.mobile).toBe('+919825669385');
    expect(user?.wallet?.walletId).toBe('wal-aa583bf2-9e66-415b-90c6-d8eda93bd540');
    expect(user?.wallet?.status).toBe('READY');

    // Zero-Address & Zero-Key Invariant Verification:
    // Ensure central database stores only opaque key references
    const keyRefs = user?.wallet?.keyReferences as Record<string, string>;
    expect(keyRefs).toBeDefined();
    expect(keyRefs.mst).toMatch(/^key-mst-/);
    expect(keyRefs.solana).toMatch(/^key-sol-/);
    expect(keyRefs.bitcoin).toMatch(/^key-btc-/);
    // Explicit check: MUST NOT contain raw addresses or private keys
    expect(JSON.stringify(keyRefs)).not.toContain('0x');
    expect(JSON.stringify(keyRefs)).not.toContain('tb1p');
  });

  it('3. User creation and mobile authentication flow via Prisma repository', async () => {
    const testMobile = '+919111222333';
    const testUser = await authRepository.createUser({
      name: 'Prisma Test User',
      mobile: testMobile,
      loginMethod: 'mobile',
    });

    expect(testUser.id).toBeDefined();
    expect(testUser.mobile).toBe(testMobile);

    // Request OTP
    const otpRes = await authService.requestPhoneOtp(testMobile);
    expect(otpRes.success).toBe(true);
    expect(otpRes.devOtp).toBeDefined();

    // Verify OTP
    const verifyRes = await authService.verifyPhoneOtp(testMobile, otpRes.devOtp!);
    expect(verifyRes.user.id).toBe(testUser.id);
    expect(verifyRes.token).toBeDefined();
    expect(verifyRes.mfaEnrolled).toBe(false);

    // Cleanup test user
    await prisma.user.delete({ where: { id: testUser.id } });
  });

  it('4. TOTP MFA enrollment and AES-256-GCM encryption at rest in Prisma', async () => {
    const tempUser = await authRepository.createUser({
      mobile: '+919444555666',
      loginMethod: 'mobile',
    });

    const enrollment = await mfaService.enrollTotp(tempUser.id);
    expect(enrollment.secret).toBeDefined();
    expect(enrollment.recoveryCodes.length).toBe(8);
    expect(enrollment.qrUri).toContain('otpauth://totp/');

    // Inspect database record: Secret MUST be encrypted at rest, recovery codes hashed
    const dbMfa = await prisma.mFAEnrollment.findUnique({
      where: { userId: tempUser.id },
    });
    expect(dbMfa).toBeDefined();
    expect(dbMfa?.totpSecretEncrypted).not.toBe(enrollment.secret);
    expect(dbMfa?.totpSecretEncrypted).toContain(':'); // iv:tag:ciphertext

    // Decrypt and verify matching secret
    const decrypted = decryptTotpSecret(dbMfa!.totpSecretEncrypted!);
    expect(decrypted).toBe(enrollment.secret);

    // Verify TOTP challenge
    const devOtp = enrollment.devOtp!;
    const verifyMfaRes = await mfaService.verifyMfaChallenge(tempUser.id, devOtp);
    expect(verifyMfaRes.success).toBe(true);
    expect(verifyMfaRes.methodUsed).toBe('totp');

    // Cleanup
    await prisma.user.delete({ where: { id: tempUser.id } });
  });

  it('5. Working policy evaluation and access audit logging via Prisma', async () => {
    const tempUser = await authRepository.createUser({
      mobile: '+919777888999',
      loginMethod: 'mobile',
    });

    await policyService.upsertPolicy({
      userId: tempUser.id,
      startTime: '00:00',
      endTime: '23:59',
      timezone: 'Asia/Kolkata',
      city: 'Indore',
      lat: 22.7196,
      lng: 75.8577,
      radiusKm: 50,
      timeRestrictionEnabled: true,
      geofenceEnabled: true,
      locationRestrictionEnabled: true,
    });

    // Evaluate policy at allowed location
    const allowedEval = await policyService.evaluateWorkingPolicy(tempUser.id, 22.72, 75.86);
    expect(allowedEval.allowed).toBe(true);

    // Evaluate policy at disallowed distant location (Fail-Closed)
    const deniedEval = await policyService.evaluateWorkingPolicy(tempUser.id, 28.6139, 77.209);
    expect(deniedEval.allowed).toBe(false);
    expect(deniedEval.reason).toContain('exceeding max allowed radius');

    // Verify access logs in database
    const logs = await prisma.accessLog.findMany({
      where: { userId: tempUser.id },
      orderBy: { attemptedAt: 'desc' },
    });
    expect(logs.length).toBe(2);
    expect(logs[0].allowed).toBe(false);
    expect(logs[1].allowed).toBe(true);

    // Cleanup
    await prisma.user.delete({ where: { id: tempUser.id } });
  });

  it('6. Strict One-User-One-Wallet Idempotent Creation & Recomputation via Prisma', async () => {
    const tempUser = await authRepository.createUser({
      mobile: '+919333444555',
      loginMethod: 'mobile',
    });

    // 1st Call: Creates new wallet
    const res1 = await walletService.createOrGetWallet(tempUser.id);
    expect(res1.isNew).toBe(true);
    expect(res1.wallet.walletId).toMatch(/^wal-/);
    const mstAddr1 = res1.addresses.mst.address;
    const solAddr1 = res1.addresses.solana.address;
    const btcAddr1 = res1.addresses.bitcoin.address;

    // 2nd Call: Idempotently retrieves exact same wallet and addresses without duplicate DKG
    const res2 = await walletService.createOrGetWallet(tempUser.id);
    expect(res2.isNew).toBe(false);
    expect(res2.wallet.walletId).toBe(res1.wallet.walletId);
    expect(res2.addresses.mst.address).toBe(mstAddr1);
    expect(res2.addresses.solana.address).toBe(solAddr1);
    expect(res2.addresses.bitcoin.address).toBe(btcAddr1);

    // Confirm DB has exactly one wallet row for this user
    const dbWallets = await prisma.walletIdentity.findMany({
      where: { userId: tempUser.id },
    });
    expect(dbWallets.length).toBe(1);

    // Cleanup
    await prisma.user.delete({ where: { id: tempUser.id } });
  });
});
