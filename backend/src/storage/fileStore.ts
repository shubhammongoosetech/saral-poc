/**
 * fileStore.ts
 *
 * Hardened Atomic Encrypted Node File Storage Engine.
 *
 * Patent & Specification Mandates (Section 2.3, Claim 1, Paragraph [0018]):
 *   1. Atomic writes: write to temp file, fsync, atomic rename. No partial reads.
 *   2. File mode 0600 (owner rw only), directory mode 0700 (owner rwx only).
 *   3. Per-node key derived with scrypt from a per-node secret (never a global master key).
 *   4. AES-256-GCM with unique random 96-bit IV.
 *   5. walletId and epoch bound as Additional Authenticated Data (AAD) so shares
 *      cannot be swapped between wallets or across epochs.
 *   6. Integrity check on every read; corruption and tampering detection.
 *   7. Path convention: data/<domain>/<nodeId>/wallets/<walletId>/share.enc and meta.json.
 */

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { DomainType } from '../crypto/thresholdEcdsa';

export interface ShareMetadata {
  version: 'v1';
  walletId: string;
  epoch: number;
  nodeId: string;
  domain: DomainType;
  shareIndex: number;
  cipherLength: number;
  checksumSha256: string;
  updatedAt: string;
}

export interface StoredEncryptedSharePayload {
  version: 'v1';
  iv: string;       // 12-byte hex
  authTag: string;  // 16-byte hex
  ciphertext: string;
}

export class NodeFileStore {
  private baseDataDir: string;
  private nodeKeysCache = new Map<string, Buffer>();

  constructor(customBaseDir?: string) {
    if (customBaseDir) {
      this.baseDataDir = customBaseDir;
    } else if (process.env.SARAL_DATA_DIR) {
      this.baseDataDir = path.resolve(process.env.SARAL_DATA_DIR);
    } else {
      // Anchor permanently to the single project root data/ directory (outside backend/)
      const projectRoot = fs.existsSync(path.resolve(process.cwd(), 'backend')) && fs.existsSync(path.resolve(process.cwd(), 'packages'))
        ? process.cwd()
        : path.resolve(__dirname, '../../..');
      this.baseDataDir = path.resolve(projectRoot, 'data');
    }
    this.ensureDir(this.baseDataDir, 0o700);
  }

  /**
   * Ensures a directory exists with the specified POSIX permissions (default 0o700).
   */
  private ensureDir(dirPath: string, mode: number = 0o700): void {
    if (!fs.existsSync(dirPath)) {
      fs.mkdirSync(dirPath, { recursive: true, mode });
    }
    try {
      fs.chmodSync(dirPath, mode);
    } catch {}
  }

  /**
   * Returns the node's dedicated root directory: data/<domain>/<nodeId>/
   */
  public getNodeDir(domain: DomainType, nodeId: string): string {
    const dir = path.join(this.baseDataDir, domain.toLowerCase(), nodeId);
    this.ensureDir(dir, 0o700);
    return dir;
  }

  /**
   * Retrieves or initializes the isolated per-node secret at data/<domain>/<nodeId>/.node_secret.
   * Mode 0600. Never uses a global master key.
   */
  public getOrCreateNodeSecret(domain: DomainType, nodeId: string): string {
    const nodeDir = this.getNodeDir(domain, nodeId);
    const secretPath = path.join(nodeDir, '.node_secret');

    if (fs.existsSync(secretPath)) {
      return fs.readFileSync(secretPath, 'utf8').trim();
    }

    // Generate fresh cryptographically secure 256-bit random secret
    const freshSecret = crypto.randomBytes(32).toString('hex');
    this.atomicWriteFile(secretPath, freshSecret, 0o600);
    return freshSecret;
  }

  /**
   * Derives a dedicated 256-bit AES-GCM storage key for the node using scrypt.
   * Parameterized with N=16384, r=8, p=1 for memory hardness.
   */
  public deriveNodeKey(domain: DomainType, nodeId: string): Buffer {
    const cacheKey = `${domain}:${nodeId}`;
    let cached = this.nodeKeysCache.get(cacheKey);
    if (cached) return cached;

    const secret = this.getOrCreateNodeSecret(domain, nodeId);
    const salt = `saral-node-storage-${domain.toLowerCase()}-${nodeId}`;
    const key = crypto.scryptSync(secret, salt, 32, { N: 16384, r: 8, p: 1 });

    this.nodeKeysCache.set(cacheKey, key);
    return key;
  }

  /**
   * Constructs Additional Authenticated Data (AAD) binding walletId and epoch.
   * Proves cryptographically that this share cannot be moved to another wallet or epoch.
   */
  private constructAad(walletId: string, epoch: number, domain: DomainType, nodeId: string): Buffer {
    return Buffer.from(`SARAL_AAD:${walletId}:EPOCH_${epoch}:${domain}:${nodeId}`, 'utf8');
  }

  /**
   * Atomically writes data to a file by writing to a temporary file, fsyncing,
   * and renaming to destination. File mode 0o600.
   */
  private atomicWriteFile(filePath: string, content: string, mode: number = 0o600): void {
    const dir = path.dirname(filePath);
    this.ensureDir(dir, 0o700);

    const tempPath = `${filePath}.tmp.${crypto.randomBytes(6).toString('hex')}`;
    const fd = fs.openSync(tempPath, 'w', mode);
    try {
      fs.writeSync(fd, content, 0, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }

    // Atomic filesystem swap
    fs.renameSync(tempPath, filePath);
    try {
      fs.chmodSync(filePath, mode);
    } catch {}
  }

  /**
   * Atomically writes and encrypts a tenant share for a specific wallet and epoch.
   */
  public writeShare(
    domain: DomainType,
    nodeId: string,
    walletId: string,
    epoch: number,
    shareIndex: number,
    plaintextShare: string
  ): ShareMetadata {
    const nodeDir = this.getNodeDir(domain, nodeId);
    const walletDir = path.join(nodeDir, 'wallets', walletId);
    this.ensureDir(walletDir, 0o700);

    const sharePath = path.join(walletDir, 'share.enc');
    const metaPath = path.join(walletDir, 'meta.json');

    // 1. Derive per-node encryption key
    const nodeKey = this.deriveNodeKey(domain, nodeId);

    // 2. Sample unique 96-bit IV
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', nodeKey, iv);

    // 3. Bind walletId and epoch into AAD
    const aad = this.constructAad(walletId, epoch, domain, nodeId);
    cipher.setAAD(aad);

    // 4. Encrypt with zeroization
    const plainBuf = Buffer.from(plaintextShare, 'utf8');
    let encrypted: Buffer;
    try {
      encrypted = Buffer.concat([cipher.update(plainBuf), cipher.final()]);
    } finally {
      plainBuf.fill(0);
    }

    const authTag = cipher.getAuthTag();
    const payload: StoredEncryptedSharePayload = {
      version: 'v1',
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      ciphertext: encrypted.toString('hex'),
    };

    const payloadString = JSON.stringify(payload);
    const checksum = crypto.createHash('sha256').update(payloadString).digest('hex');

    const metadata: ShareMetadata = {
      version: 'v1',
      walletId,
      epoch,
      nodeId,
      domain,
      shareIndex,
      cipherLength: encrypted.length,
      checksumSha256: checksum,
      updatedAt: new Date().toISOString(),
    };

    // 5. Atomic writes
    this.atomicWriteFile(sharePath, payloadString, 0o600);
    this.atomicWriteFile(metaPath, JSON.stringify(metadata, null, 2), 0o600);

    return metadata;
  }

  /**
   * Reads, verifies, and decrypts an encrypted share.
   * Enforces integrity check, AAD validation (walletId + epoch), and corruption detection.
   */
  public readShare(
    domain: DomainType,
    nodeId: string,
    walletId: string,
    expectedEpoch?: number
  ): { plaintextShare: string; metadata: ShareMetadata } {
    const nodeDir = this.getNodeDir(domain, nodeId);
    const walletDir = path.join(nodeDir, 'wallets', walletId);
    const sharePath = path.join(walletDir, 'share.enc');
    const metaPath = path.join(walletDir, 'meta.json');

    if (!fs.existsSync(sharePath) || !fs.existsSync(metaPath)) {
      throw new Error(`[FileStore] Share files not found for wallet '${walletId}' on node '${nodeId}'`);
    }

    // 1. Read and parse metadata
    const metaContent = fs.readFileSync(metaPath, 'utf8');
    let meta: ShareMetadata;
    try {
      meta = JSON.parse(metaContent);
    } catch {
      throw new Error(`[FileStore] Corrupted metadata file on node '${nodeId}' for wallet '${walletId}'`);
    }

    // 2. Validate epoch freshness if specified
    if (expectedEpoch !== undefined && meta.epoch !== expectedEpoch) {
      throw new Error(
        `[FileStore] Stale share epoch on node '${nodeId}': found epoch ${meta.epoch}, required ${expectedEpoch}`
      );
    }

    // 3. Read share file & verify SHA-256 integrity tag
    const shareContent = fs.readFileSync(sharePath, 'utf8');
    const actualChecksum = crypto.createHash('sha256').update(shareContent).digest('hex');
    if (actualChecksum !== meta.checksumSha256) {
      throw new Error(
        `[FileStore] Share integrity checksum mismatch on node '${nodeId}': file corrupted or modified externally`
      );
    }

    let payload: StoredEncryptedSharePayload;
    try {
      payload = JSON.parse(shareContent);
    } catch {
      throw new Error(`[FileStore] Corrupted encrypted share payload JSON on node '${nodeId}'`);
    }

    // 4. Derive per-node key
    const nodeKey = this.deriveNodeKey(domain, nodeId);
    const iv = Buffer.from(payload.iv, 'hex');
    const authTag = Buffer.from(payload.authTag, 'hex');
    const cipherBuf = Buffer.from(payload.ciphertext, 'hex');

    // 5. Decipher and strictly verify AAD binding
    const decipher = crypto.createDecipheriv('aes-256-gcm', nodeKey, iv);
    decipher.setAuthTag(authTag);

    const aad = this.constructAad(walletId, meta.epoch, domain, nodeId);
    decipher.setAAD(aad);

    try {
      const decrypted = Buffer.concat([decipher.update(cipherBuf), decipher.final()]);
      const plaintext = decrypted.toString('utf8');
      decrypted.fill(0);
      return { plaintextShare: plaintext, metadata: meta };
    } catch (err: any) {
      throw new Error(
        `[FileStore] Cryptographic authentication tag verification failed on node '${nodeId}': ` +
        `share ciphertext was tampered with, or swapped between wallets/epochs.`
      );
    }
  }

  /**
   * Deletes a tenant's share securely upon proactive resharing or wallet deallocation.
   */
  public deleteShare(domain: DomainType, nodeId: string, walletId: string): void {
    const walletDir = path.join(this.getNodeDir(domain, nodeId), 'wallets', walletId);
    if (fs.existsSync(walletDir)) {
      const sharePath = path.join(walletDir, 'share.enc');
      const metaPath = path.join(walletDir, 'meta.json');
      try {
        if (fs.existsSync(sharePath)) fs.unlinkSync(sharePath);
        if (fs.existsSync(metaPath)) fs.unlinkSync(metaPath);
        fs.rmdirSync(walletDir);
      } catch {}
    }
  }

  /**
   * Health check for a node's storage partition.
   */
  public checkNodeHealth(domain: DomainType, nodeId: string): { healthy: boolean; nodeDir: string; totalWallets: number } {
    const nodeDir = this.getNodeDir(domain, nodeId);
    const walletsDir = path.join(nodeDir, 'wallets');
    this.ensureDir(walletsDir, 0o700);

    const wallets = fs.readdirSync(walletsDir).filter((f) => {
      const p = path.join(walletsDir, f);
      return fs.statSync(p).isDirectory();
    });

    return {
      healthy: true,
      nodeDir,
      totalWallets: wallets.length,
    };
  }
}

// Global FileStore singleton
export const nodeFileStore = new NodeFileStore();

