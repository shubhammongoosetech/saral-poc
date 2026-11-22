/**
 * SARAL Protocol — Hardened Application Store & In-Memory Cache
 * Backed by Prisma ORM and PostgreSQL
 *
 * MANDATES:
 * 1. Zero-Address Storage: Central database stores ZERO wallet addresses and ZERO public keys.
 *    Only opaque key references are persisted.
 * 2. Prisma ORM: All database persistence operations are executed through Prisma Client.
 * 3. Fail-Closed / High Performance In-Memory Sync for sub-millisecond route resolution.
 */

import crypto from 'crypto';
import type { Prisma, WalletIdentity, WorkingPolicy } from '@prisma/client';
import { prisma } from '../database/prisma';
import type { WalletMeshReferences } from '../config/wallet';

export function toPrismaUuid(id: string): string {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    return id;
  }
  const hash = crypto.createHash('md5').update(id).digest('hex');
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-4${hash.slice(13, 16)}-a${hash.slice(17, 20)}-${hash.slice(20, 32)}`;
}

export interface UserRecord {
  id: string;
  name?: string;
  email?: string;
  googleId?: string;
  mobile?: string;
  loginMethod: 'google' | 'mobile';
  createdAt: string;
  updatedAt: string;
}

export interface MfaRecord {
  userId: string;
  type: 'totp' | 'otp';
  verifiedAt?: string;
  totpSecretEncrypted?: string;
  recoveryCodesHashed?: string[];
  updatedAt: string;
}

export interface WorkingPolicyRecord {
  userId: string;
  timeRestrictionEnabled: boolean;
  startTime: string;
  endTime: string;
  days: string[];
  timezone: string;
  expiresAt?: string;
  locationRestrictionEnabled: boolean;
  allowedRegion?: string;
  geofenceEnabled?: boolean;
  lat?: number;
  lng?: number;
  radiusMeters?: number;
  updatedAt: string;
}

export interface WalletMetadataRecord {
  userId: string;
  walletId: string;
  status:
    | 'NOT_CREATED'
    | 'CREATING'
    | 'DKG_IN_PROGRESS'
    | 'KEY_READY'
    | 'DERIVING_ADDRESS'
    | 'READY'
    | 'UNAVAILABLE'
    | 'ERROR'
    | string;
  error?: string;
  keyReferences: {
    mst?: string;
    solana?: string;
    bitcoin?: string;
    dkgSessionId?: string;
    mstSessionId?: string;
    solanaSessionId?: string;
    bitcoinSessionId?: string;
    mesh?: WalletMeshReferences;
  };
  createdAt: string;
  updatedAt: string;
}

export interface AccessLogRecord {
  id: string;
  userId: string;
  attemptedAt: string;
  lat?: number;
  lng?: number;
  allowed: boolean;
  reason: string;
}

export interface SecurityLogRecord {
  id: string;
  userId: string;
  eventType: string;
  severity: 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';
  ip?: string;
  userAgent?: string;
  details?: Record<string, unknown>;
  timestamp: string;
}

export interface OtpRecord {
  id: string;
  userId: string;
  mobile: string;
  codeHash: string;
  purpose: 'login' | 'mfa';
  expiresAt: number;
  used: boolean;
  attempts: number;
  createdAt: number;
}

interface StoreSchema {
  version: number;
  users: Record<string, UserRecord>;
  mfa: Record<string, MfaRecord>;
  policies: Record<string, WorkingPolicyRecord>;
  wallets: Record<string, WalletMetadataRecord>;
  otps: Record<string, OtpRecord>;
  accessLogs: AccessLogRecord[];
  securityLogs: SecurityLogRecord[];
}

export class DataStore {
  private static instance: DataStore;
  private data: StoreSchema;

  private constructor() {
    this.data = {
      version: 1,
      users: {},
      mfa: {},
      policies: {},
      wallets: {},
      otps: {},
      accessLogs: [],
      securityLogs: [],
    };
  }

  public static getInstance(): DataStore {
    if (!DataStore.instance) {
      DataStore.instance = new DataStore();
    }
    return DataStore.instance;
  }

  private persist(): void {
    // In-memory cache is synchronized directly with PostgreSQL through Prisma Client.
    // Zero filesystem writes and zero disk JSON file persistence.
  }

  // --- Users ---
  public findUserById(userId: string): UserRecord | null {
    return this.data.users[userId] || null;
  }

  public findUserByEmail(email: string): UserRecord | null {
    const clean = email.toLowerCase().trim();
    for (const u of Object.values(this.data.users)) {
      if (u.email && u.email.toLowerCase() === clean) return u;
    }
    return null;
  }

  public findUserByGoogleId(googleId: string): UserRecord | null {
    for (const u of Object.values(this.data.users)) {
      if (u.googleId === googleId) return u;
    }
    return null;
  }

  public findUserByMobile(mobile: string): UserRecord | null {
    for (const u of Object.values(this.data.users)) {
      if (u.mobile === mobile) return u;
    }
    return null;
  }

  public async syncFromPostgres(): Promise<void> {
    try {
      // Sync users via Prisma
      const users = await prisma.user.findMany();
      for (const u of users) {
        this.data.users[u.id] = {
          id: u.id,
          name: u.name || undefined,
          googleId: u.googleId || undefined,
          email: u.email || undefined,
          mobile: u.mobile || undefined,
          loginMethod: u.loginMethod as any,
          createdAt: u.createdAt.toISOString(),
          updatedAt: u.createdAt.toISOString(),
        };
      }

      // Sync MFA via Prisma
      const mfas = await prisma.mFAEnrollment.findMany();
      for (const m of mfas) {
        this.data.mfa[m.userId] = {
          userId: m.userId,
          type: (m.type as any) || 'totp',
          totpSecretEncrypted: m.totpSecretEncrypted || undefined,
          recoveryCodesHashed: m.recoveryCodesHashed || [],
          verifiedAt: m.verifiedAt ? m.verifiedAt.toISOString() : undefined,
          updatedAt: new Date().toISOString(),
        };
      }

      // Sync Policies via Prisma
      const policies = await prisma.workingPolicy.findMany();
      for (const p of policies) {
        this.cachePolicy(p.userId, p);
      }

      // Sync Wallets via Prisma
      const wallets = await prisma.walletIdentity.findMany();
      for (const w of wallets) {
        this.cacheWallet(w.userId, w);
      }

      console.log(
        `[DataStore] Prisma ORM synced: ${users.length} users, ${wallets.length} wallets, ${mfas.length} MFAs`
      );
    } catch (err: any) {
      throw new Error('Could not load the auth server data from PostgreSQL', { cause: err });
    }
  }

  public async saveUser(user: UserRecord): Promise<void> {
    const prismaId = toPrismaUuid(user.id);
    await prisma.user.upsert({
      where: { id: prismaId },
      create: {
        id: prismaId,
        name: user.name,
        googleId: user.googleId,
        email: user.email,
        mobile: user.mobile,
        loginMethod: user.loginMethod,
      },
      update: {
        name: user.name,
        googleId: user.googleId,
        email: user.email,
        mobile: user.mobile,
        loginMethod: user.loginMethod,
      },
    });
    this.data.users[user.id] = user;
  }

  public async findPersistedUser(where: Prisma.UserWhereUniqueInput): Promise<UserRecord | null> {
    const user = await prisma.user.findUnique({ where });
    if (!user) return null;
    const record: UserRecord = {
      id: user.id,
      name: user.name ?? undefined,
      email: user.email ?? undefined,
      googleId: user.googleId ?? undefined,
      mobile: user.mobile ?? undefined,
      loginMethod: user.loginMethod as UserRecord['loginMethod'],
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.createdAt.toISOString(),
    };
    this.data.users[record.id] = record;
    return record;
  }

  public async attachGoogleIdentity(userId: string, googleId: string): Promise<UserRecord> {
    const result = await prisma.user.updateMany({
      where: { id: toPrismaUuid(userId), OR: [{ googleId: null }, { googleId }] },
      data: { googleId },
    });
    if (result.count !== 1) throw new Error('A Google identity is already linked to this account');
    const user = await this.findPersistedUser({ id: toPrismaUuid(userId) });
    if (!user) throw new Error('User not found');
    return user;
  }

  // --- MFA ---
  public getMfa(userId: string): MfaRecord | null {
    return this.data.mfa[userId] || null;
  }

  public async findPersistedMfa(userId: string): Promise<MfaRecord | null> {
    const mfa = await prisma.mFAEnrollment.findUnique({ where: { userId: toPrismaUuid(userId) } });
    if (!mfa) {
      delete this.data.mfa[userId];
      return null;
    }
    const record: MfaRecord = {
      userId,
      type: mfa.type as MfaRecord['type'],
      verifiedAt: mfa.verifiedAt?.toISOString(),
      totpSecretEncrypted: mfa.totpSecretEncrypted ?? undefined,
      recoveryCodesHashed: mfa.recoveryCodesHashed,
      updatedAt: mfa.verifiedAt?.toISOString() ?? new Date().toISOString(),
    };
    this.data.mfa[userId] = record;
    return record;
  }

  public async saveMfa(record: MfaRecord): Promise<void> {
    const userId = toPrismaUuid(record.userId);
    const data = {
      type: record.type,
      totpSecretEncrypted: record.totpSecretEncrypted,
      recoveryCodesHashed: record.recoveryCodesHashed ?? [],
    };
    const pending = await prisma.mFAEnrollment.updateMany({ where: { userId, verifiedAt: null }, data });
    if (pending.count === 0) {
      try {
        await prisma.mFAEnrollment.create({ data: { userId, ...data } });
      } catch (err) {
        if (typeof err === 'object' && err && 'code' in err && err.code === 'P2002') {
          throw new Error('MFA is already enrolled or another setup request is in progress');
        }
        throw err;
      }
    }
    this.data.mfa[record.userId] = record;
  }

  public async saveVerifiedMfa(previous: MfaRecord, verifiedAt: Date, recoveryCodes: string[], usedRecoveryCode?: string): Promise<boolean> {
    const result = await prisma.mFAEnrollment.updateMany({
      where: {
        userId: toPrismaUuid(previous.userId),
        totpSecretEncrypted: previous.totpSecretEncrypted ?? null,
        verifiedAt: previous.verifiedAt ? new Date(previous.verifiedAt) : null,
        recoveryCodesHashed: { equals: previous.recoveryCodesHashed ?? [] },
        recoveryCodeRecords: usedRecoveryCode ? { none: { codeHash: usedRecoveryCode, used: true } } : undefined,
      },
      data: { verifiedAt, recoveryCodesHashed: recoveryCodes },
    });
    if (result.count !== 1) return false;
    this.data.mfa[previous.userId] = {
      ...previous,
      verifiedAt: verifiedAt.toISOString(),
      recoveryCodesHashed: recoveryCodes,
      updatedAt: new Date().toISOString(),
    };
    return true;
  }

  // --- Working Policy ---
  public getPolicy(userId: string): WorkingPolicyRecord | null {
    return this.data.policies[userId] || null;
  }

  private cachePolicy(userId: string, row: WorkingPolicy): WorkingPolicyRecord {
    const policy: WorkingPolicyRecord = {
      userId,
      timeRestrictionEnabled: row.timeRestrictionEnabled,
      startTime: row.startTime,
      endTime: row.endTime,
      days: row.days,
      timezone: row.timezone,
      expiresAt: row.expiresAt?.toISOString(),
      locationRestrictionEnabled: row.locationRestrictionEnabled,
      allowedRegion: row.city,
      geofenceEnabled: row.geofenceEnabled,
      lat: row.lat,
      lng: row.lng,
      radiusMeters: row.radiusKm * 1000,
      updatedAt: row.setAt.toISOString(),
    };
    this.data.policies[userId] = policy;
    return policy;
  }

  public async loadPolicy(userId: string): Promise<WorkingPolicyRecord | null> {
    const row = await prisma.workingPolicy.findUnique({ where: { userId: toPrismaUuid(userId) } });
    if (!row) {
      delete this.data.policies[userId];
      return null;
    }
    return this.cachePolicy(userId, row);
  }

  public async savePolicy(policy: WorkingPolicyRecord): Promise<void> {
    const userId = toPrismaUuid(policy.userId);
    const data = {
      startTime: policy.startTime,
      endTime: policy.endTime,
      timezone: policy.timezone,
      city: policy.allowedRegion ?? 'Primary Workspace',
      lat: policy.lat ?? 0,
      lng: policy.lng ?? 0,
      radiusKm: (policy.radiusMeters ?? 25000) / 1000,
      timeRestrictionEnabled: policy.timeRestrictionEnabled,
      locationRestrictionEnabled: policy.locationRestrictionEnabled,
      geofenceEnabled: policy.geofenceEnabled ?? false,
      days: policy.days,
      expiresAt: policy.expiresAt ? new Date(policy.expiresAt) : null,
      setAt: new Date(),
    };
    const row = await prisma.workingPolicy.upsert({
      where: { userId },
      create: { userId, ...data },
      update: data,
    });
    this.cachePolicy(policy.userId, row);
  }

  // --- Wallet Metadata (One-User-One-Wallet) ---
  public getWalletByUserId(userId: string): WalletMetadataRecord | null {
    return this.data.wallets[userId] || null;
  }

  private cacheWallet(userId: string, row: WalletIdentity): WalletMetadataRecord {
    const wallet: WalletMetadataRecord = {
      userId,
      walletId: row.walletId,
      status: row.status,
      keyReferences: (row.keyReferences || {}) as WalletMetadataRecord['keyReferences'],
      createdAt: row.createdAt.toISOString(),
      updatedAt: row.updatedAt.toISOString(),
    };
    this.data.wallets[userId] = wallet;
    return wallet;
  }

  public async loadWallet(userId: string): Promise<WalletMetadataRecord | null> {
    const row = await prisma.walletIdentity.findUnique({ where: { userId: toPrismaUuid(userId) } });
    if (!row) {
      delete this.data.wallets[userId];
      return null;
    }
    return this.cacheWallet(userId, row);
  }

  public async reserveWallet(record: WalletMetadataRecord): Promise<WalletMetadataRecord> {
    const userId = await this.ensureUserInPrisma(record.userId);
    if (!userId) throw new Error('Could not resolve the wallet owner.');
    try {
      const row = await prisma.walletIdentity.create({
        data: {
          userId,
          walletId: record.walletId,
          status: record.status,
          keyReferences: record.keyReferences,
        },
      });
      return this.cacheWallet(record.userId, row);
    } catch (error) {
      // Another request may have won the unique user_id reservation.
      if ((error as { code?: string }).code === 'P2002') {
        const existing = await this.loadWallet(record.userId);
        if (existing) return existing;
      }
      throw error;
    }
  }

  public async transitionWallet(
    wallet: WalletMetadataRecord,
    expectedStatuses: string[],
    status: string,
  ): Promise<WalletMetadataRecord> {
    await prisma.walletIdentity.updateMany({
      where: {
        userId: toPrismaUuid(wallet.userId),
        walletId: wallet.walletId,
        status: { in: expectedStatuses },
      },
      data: { status, updatedAt: new Date() },
    });
    const updated = await this.loadWallet(wallet.userId);
    if (!updated || updated.walletId !== wallet.walletId) {
      throw new Error('Could not resolve the reserved wallet.');
    }
    return updated;
  }

  // --- OTP Management ---
  public getActiveOtp(userId: string, purpose: 'login' | 'mfa'): OtpRecord | null {
    const now = Date.now();
    for (const otp of Object.values(this.data.otps)) {
      if (otp.userId === userId && otp.purpose === purpose && !otp.used && otp.expiresAt > now) {
        return otp;
      }
    }
    return null;
  }

  public async saveOtp(record: OtpRecord): Promise<void> {
    const prismaUserId = toPrismaUuid(record.userId);
    await prisma.oTPChallenge.create({
      data: {
        id: toPrismaUuid(record.id),
        userId: prismaUserId,
        code: record.codeHash,
        purpose: record.purpose,
        expiresAt: new Date(record.expiresAt),
        used: record.used,
      },
    });
    const now = Date.now();
    for (const previous of Object.values(this.data.otps)) {
      if (previous.used || previous.expiresAt <= now) delete this.data.otps[previous.id];
    }
    this.data.otps[record.id] = record;
  }

  public async markOtpUsed(id: string): Promise<boolean> {
    const otp = this.data.otps[id];
    if (!otp || otp.used) return false;
    otp.used = true;
    const result = await prisma.oTPChallenge.updateMany({
      where: { id: toPrismaUuid(id), used: false, expiresAt: { gt: new Date() } },
      data: { used: true },
    });
    return result.count === 1;
  }

  public incrementOtpAttempts(id: string): number {
    if (this.data.otps[id]) {
      this.data.otps[id].attempts += 1;
      this.persist();
      return this.data.otps[id].attempts;
    }
    return 0;
  }

  private async ensureUserInPrisma(userId: string): Promise<string | null> {
    const prismaUserId = toPrismaUuid(userId);
    try {
      const existing = await prisma.user.findUnique({ where: { id: prismaUserId } });
      if (existing) return existing.id;

      const user = this.data.users[userId];
      const created = await prisma.user.create({
        data: {
          id: prismaUserId,
          name: user?.name || `SARAL User ${userId.slice(0, 8)}`,
          googleId: user?.googleId || `dev-${prismaUserId}`,
          email: user?.email || `dev-${prismaUserId}@saral.network`,
          mobile: user?.mobile || null,
          loginMethod: user?.loginMethod || 'google',
        },
      });
      return created.id;
    } catch (_) {
      const check = await prisma.user.findUnique({ where: { id: prismaUserId } }).catch(() => null);
      return check ? check.id : null;
    }
  }

  // --- Access & Audit Logs ---
  public logAccess(record: AccessLogRecord): void {
    this.data.accessLogs.push(record);
    if (this.data.accessLogs.length > 1000) {
      this.data.accessLogs = this.data.accessLogs.slice(-1000);
    }
    this.persist();

    const prismaId = toPrismaUuid(record.id);
    this.ensureUserInPrisma(record.userId)
      .then((prismaUserId) => {
        if (!prismaUserId) return;
        return prisma.accessLog.create({
          data: {
            id: prismaId,
            userId: prismaUserId,
            attemptedAt: new Date(record.attemptedAt),
            lat: record.lat,
            lng: record.lng,
            allowed: record.allowed,
            reason: record.reason,
          },
        });
      })
      .catch(() => {});
  }

  public logSecurity(record: SecurityLogRecord): void {
    this.data.securityLogs.push(record);
    if (this.data.securityLogs.length > 1000) {
      this.data.securityLogs = this.data.securityLogs.slice(-1000);
    }
    this.persist();

    const prismaId = toPrismaUuid(record.id);
    this.ensureUserInPrisma(record.userId)
      .then((prismaUserId) => {
        if (!prismaUserId) return;
        return prisma.securityAuditEvent.create({
          data: {
            id: prismaId,
            userId: prismaUserId,
            eventType: record.eventType,
            severity: record.severity,
            ipAddress: record.ip,
            userAgent: record.userAgent,
            details: record.details ? JSON.stringify(record.details) : undefined,
            createdAt: new Date(record.timestamp),
          },
        });
      })
      .catch(() => {});
  }
}
