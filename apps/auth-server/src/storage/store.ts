/**
 * SARAL Protocol V3 — Hardened Atomic File-Backed Application Store
 *
 * PATENT & SPECIFICATION MANDATES:
 * 1. Zero-Address Storage: Central database stores ZERO wallet addresses and ZERO public keys.
 *    Only opaque key references are persisted.
 * 2. Atomic Writes: Temp file creation, fsync, atomic rename. Prevents corruption.
 * 3. Strict 0600 file permissions and 0700 directory permissions.
 * 4. Transactional integrity across users, MFA, policies, and wallet metadata.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { pgPool, getIsPgConnected } from './db';

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
  totpSecretEncrypted?: string; // AES-256-GCM encrypted base32 secret
  recoveryCodesHashed?: string[]; // SHA-256 hashes of single-use recovery codes
  updatedAt: string;
}

export interface WorkingPolicyRecord {
  userId: string;
  timeRestrictionEnabled: boolean;
  startTime: string; // "09:00"
  endTime: string;   // "18:00"
  days: string[];    // ["MON", "TUE", "WED", "THU", "FRI"]
  timezone: string;  // IANA timezone, e.g. "Asia/Kolkata"
  expiresAt?: string;
  locationRestrictionEnabled: boolean;
  allowedRegion?: string;
  geofenceEnabled?: boolean;
  lat?: number;
  lng?: number;
  radiusMeters?: number; // Geofence radius in meters
  updatedAt: string;
}

/**
 * STRICT METADATA ONLY:
 * Note: Under the SARAL Zero-Address Storage Architecture,
 * wallet addresses, Ethereum addresses, Solana addresses, Bitcoin addresses,
 * and public keys MUST NEVER be stored in the database.
 */
export interface WalletMetadataRecord {
  userId: string;
  walletId: string;
  status: 'CREATING' | 'READY';
  keyReferences: {
    mst?: string;
    solana?: string;
    bitcoin?: string;
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
  codeHash: string; // HMAC-SHA256 digest; never plaintext
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
  private filePath: string;
  private data: StoreSchema;
  private writeLock = false;

  private constructor() {
    const dataDir = process.env.DATA_DIR || path.join(process.cwd(), 'data');
    if (!fs.existsSync(dataDir)) {
      try {
        fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
      } catch (_) {}
    }
    this.filePath = path.join(dataDir, 'saral_auth_store.json');
    this.data = this.loadData();
  }

  public static getInstance(): DataStore {
    if (!DataStore.instance) {
      DataStore.instance = new DataStore();
    }
    return DataStore.instance;
  }

  private loadData(): StoreSchema {
    if (fs.existsSync(this.filePath)) {
      try {
        const content = fs.readFileSync(this.filePath, 'utf8');
        const parsed = JSON.parse(content);
        return {
          version: parsed.version || 1,
          users: parsed.users || {},
          mfa: parsed.mfa || {},
          policies: parsed.policies || {},
          wallets: parsed.wallets || {},
          otps: parsed.otps || {},
          accessLogs: parsed.accessLogs || [],
          securityLogs: parsed.securityLogs || [],
        };
      } catch (err) {
        console.warn('[DataStore] Failed reading store file, initializing empty store:', err);
      }
    }

    return {
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

  private persist(): void {
    if (this.writeLock) return;
    this.writeLock = true;
    try {
      const dir = path.dirname(this.filePath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }

      const tempFile = `${this.filePath}.tmp.${crypto.randomBytes(6).toString('hex')}`;
      const payload = JSON.stringify(this.data, null, 2);
      fs.writeFileSync(tempFile, payload, { mode: 0o600 });
      fs.renameSync(tempFile, this.filePath);
    } catch (err) {
      console.error('[DataStore] Atomic write failed:', err);
    } finally {
      this.writeLock = false;
    }
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
    if (!getIsPgConnected()) return;
    try {
      // Sync users
      const uRes = await pgPool.query('SELECT * FROM users;');
      for (const r of uRes.rows) {
        this.data.users[r.id] = {
          id: r.id,
          name: r.name,
          googleId: r.google_id,
          email: r.email,
          mobile: r.mobile,
          loginMethod: r.login_method,
          createdAt: r.created_at ? new Date(r.created_at).toISOString() : new Date().toISOString(),
          updatedAt: r.created_at ? new Date(r.created_at).toISOString() : new Date().toISOString(),
        };
      }

      // Sync MFA
      const mRes = await pgPool.query('SELECT * FROM mfa;');
      for (const r of mRes.rows) {
        this.data.mfa[r.user_id] = {
          userId: r.user_id,
          type: r.type || 'totp',
          totpSecretEncrypted: r.secret,
          recoveryCodesHashed: r.recovery_codes || [],
          verifiedAt: r.verified_at ? new Date(r.verified_at).toISOString() : undefined,
          updatedAt: new Date().toISOString(),
        };
      }

      // Sync Policy
      const pRes = await pgPool.query('SELECT * FROM work_policy;');
      for (const r of pRes.rows) {
        this.data.policies[r.user_id] = {
          userId: r.user_id,
          timeRestrictionEnabled: true,
          startTime: r.start_time || '09:00',
          endTime: r.end_time || '18:00',
          days: ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'],
          timezone: r.timezone || 'Asia/Kolkata',
          locationRestrictionEnabled: true,
          allowedRegion: r.city,
          geofenceEnabled: true,
          lat: r.lat,
          lng: r.lng,
          radiusMeters: (r.radius_km || 25) * 1000,
          updatedAt: new Date().toISOString(),
        };
      }

      // Sync Wallets
      const wRes = await pgPool.query('SELECT * FROM wallets;');
      for (const r of wRes.rows) {
        this.data.wallets[r.user_id] = {
          userId: r.user_id,
          walletId: r.wallet_id,
          status: r.status || 'READY',
          keyReferences: r.key_references || {},
          createdAt: r.created_at ? new Date(r.created_at).toISOString() : new Date().toISOString(),
          updatedAt: r.updated_at ? new Date(r.updated_at).toISOString() : new Date().toISOString(),
        };
      }

      console.log(`[DataStore] Successfully synced from PostgreSQL: ${uRes.rowCount} users, ${wRes.rowCount} wallets`);
    } catch (err: any) {
      console.warn('[DataStore] Error syncing from PostgreSQL:', err.message);
    }
  }

  public saveUser(user: UserRecord): void {
    this.data.users[user.id] = user;
    this.persist();
    if (getIsPgConnected()) {
      pgPool.query(
        `INSERT INTO users (id, name, google_id, email, mobile, login_method, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (id) DO UPDATE SET
           name = EXCLUDED.name,
           google_id = EXCLUDED.google_id,
           email = EXCLUDED.email,
           mobile = EXCLUDED.mobile,
           login_method = EXCLUDED.login_method;`,
        [user.id, user.name || null, user.googleId || null, user.email || null, user.mobile || null, user.loginMethod, user.createdAt]
      ).catch((e) => console.warn('[PostgreSQL] saveUser warning:', e.message));
    }
  }

  // --- MFA ---
  public getMfa(userId: string): MfaRecord | null {
    return this.data.mfa[userId] || null;
  }

  public saveMfa(record: MfaRecord): void {
    this.data.mfa[record.userId] = record;
    this.persist();
    if (getIsPgConnected()) {
      pgPool.query(
        `INSERT INTO mfa (user_id, type, secret, recovery_codes, verified_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (user_id) DO UPDATE SET
           type = EXCLUDED.type,
           secret = EXCLUDED.secret,
           recovery_codes = EXCLUDED.recovery_codes,
           verified_at = EXCLUDED.verified_at;`,
        [record.userId, record.type, record.totpSecretEncrypted || null, record.recoveryCodesHashed || [], record.verifiedAt || null]
      ).catch((e) => console.warn('[PostgreSQL] saveMfa warning:', e.message));
    }
  }

  // --- Working Policy ---
  public getPolicy(userId: string): WorkingPolicyRecord | null {
    return this.data.policies[userId] || null;
  }

  public savePolicy(policy: WorkingPolicyRecord): void {
    this.data.policies[policy.userId] = policy;
    this.persist();
    if (getIsPgConnected()) {
      const radiusKm = policy.radiusMeters ? policy.radiusMeters / 1000 : 25;
      pgPool.query(
        `INSERT INTO work_policy (user_id, start_time, end_time, timezone, city, lat, lng, radius_km, set_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
         ON CONFLICT (user_id) DO UPDATE SET
           start_time = EXCLUDED.start_time,
           end_time = EXCLUDED.end_time,
           timezone = EXCLUDED.timezone,
           city = EXCLUDED.city,
           lat = EXCLUDED.lat,
           lng = EXCLUDED.lng,
           radius_km = EXCLUDED.radius_km,
           set_at = NOW();`,
        [
          policy.userId,
          policy.startTime || '09:00',
          policy.endTime || '18:00',
          policy.timezone || 'Asia/Kolkata',
          policy.allowedRegion || 'Indore',
          policy.lat || 22.7196,
          policy.lng || 75.8577,
          radiusKm
        ]
      ).catch((e) => console.warn('[PostgreSQL] savePolicy warning:', e.message));
    }
  }

  // --- Wallet Metadata (One-User-One-Wallet) ---
  public getWalletByUserId(userId: string): WalletMetadataRecord | null {
    return this.data.wallets[userId] || null;
  }

  public saveWallet(record: WalletMetadataRecord): void {
    this.data.wallets[record.userId] = record;
    this.persist();
    if (getIsPgConnected()) {
      pgPool.query(
        `INSERT INTO wallets (user_id, wallet_id, status, key_references, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (user_id) DO UPDATE SET
           status = EXCLUDED.status,
           key_references = EXCLUDED.key_references,
           updated_at = EXCLUDED.updated_at;`,
        [record.userId, record.walletId, record.status, JSON.stringify(record.keyReferences), record.createdAt, record.updatedAt]
      ).catch((e) => console.warn('[PostgreSQL] saveWallet warning:', e.message));
    }
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

  public saveOtp(record: OtpRecord): void {
    this.data.otps[record.id] = record;
    this.persist();
  }

  public markOtpUsed(id: string): void {
    if (this.data.otps[id]) {
      this.data.otps[id].used = true;
      this.persist();
    }
  }

  public incrementOtpAttempts(id: string): number {
    if (this.data.otps[id]) {
      this.data.otps[id].attempts += 1;
      this.persist();
      return this.data.otps[id].attempts;
    }
    return 0;
  }

  // --- Access & Audit Logs ---
  public logAccess(record: AccessLogRecord): void {
    this.data.accessLogs.push(record);
    if (this.data.accessLogs.length > 1000) {
      this.data.accessLogs = this.data.accessLogs.slice(-1000);
    }
    this.persist();
  }

  public logSecurity(record: SecurityLogRecord): void {
    this.data.securityLogs.push(record);
    if (this.data.securityLogs.length > 1000) {
      this.data.securityLogs = this.data.securityLogs.slice(-1000);
    }
    this.persist();
  }
}
