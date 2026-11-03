import { ethers } from 'ethers';
import { prisma } from '../config/db';
import { env } from '../config/env';
import {
  splitPrivateKey3Ways,
  combinePrivateKey3WaysAsBuffer,
  encryptShare,
  decryptShare,
  wipeBuffer,
} from '../utils/crypto';
import { splitSecret, reconstructSecret, validateShamirParams } from './shamirService';
import {
  createShareContainer,
  readSharesBatch,
} from './dockerService';
import { getBalance, sendTransaction } from './chainService';
import { evaluateAccessPolicy } from './locationService';

export interface WalletInfo {
  address:   string;
  publicKey: string;
  balance:   string;
  createdAt: string;
  n:         number;
  threshold: number;
}

const CATEGORIES: Array<'PUBLIC' | 'INSTITUTIONAL' | 'SOVEREIGN'> = [
  'PUBLIC', 'INSTITUTIONAL', 'SOVEREIGN',
];

// ─── Internal helpers ─────────────────────────────────────────────────────────

export async function hasExistingWallet(userId: string): Promise<boolean> {
  const count = await prisma.keyShare.count({ where: { userId } });
  return count > 0;
}

/**
 * Reconstructs all 3 parts by reading all needed shares in a SINGLE batch Docker inspect.
 * Total time: ~20-30ms!
 */
async function reconstructAllPartsFromContainers(
  userId: string,
  threshold: number
): Promise<Record<string, string>> {
  // 1. Fetch threshold container names for all categories in parallel
  const categoryRows = await Promise.all(
    CATEGORIES.map(async (cat) => {
      const rows = await prisma.keyShare.findMany({
        where:   { userId, category: cat },
        orderBy: { shareIndex: 'asc' },
        take:    threshold,
        select:  { containerName: true },
      });
      if (rows.length < threshold) {
        throw new Error(
          `Insufficient shares for category ${cat}: need ${threshold}, found ${rows.length}`
        );
      }
      return { category: cat, rows };
    })
  );

  // 2. Collect all container names to inspect in ONE single batch call
  const allContainerNames = categoryRows.flatMap((c) =>
    c.rows.map((r) => r.containerName)
  );

  // 3. Ultra-fast batch inspect across all containers (20-30ms)
  const sharesMap = await readSharesBatch(allContainerNames);

  // 4. Decrypt and reconstruct each category's secret via Shamir
  const reconstructedParts: Record<string, string> = {};

  for (const { category, rows } of categoryRows) {
    const decryptedShares = rows.map((r) => {
      const encrypted = sharesMap.get(r.containerName);
      if (!encrypted) {
        throw new Error(`Missing share from container ${r.containerName}`);
      }
      return decryptShare(encrypted);
    });

    reconstructedParts[category] = reconstructSecret(decryptedShares);
  }

  return reconstructedParts;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Reconstructs wallet address + public key on-the-fly from Docker containers.
 * Reads in ~30ms using batch container inspection.
 */
export async function getExistingWallet(userId: string): Promise<WalletInfo | null> {
  const first = await prisma.keyShare.findFirst({
    where:  { userId },
    select: { n: true, threshold: true, createdAt: true },
  });
  if (!first) return null;

  const { n, threshold, createdAt } = first;

  let reconstructedParts: Record<string, string> = {};
  let keyBuffer: Buffer | null = null;

  try {
    reconstructedParts = await reconstructAllPartsFromContainers(userId, threshold);

    // Reconstruct into a secure, zeroizable 32-byte Buffer
    keyBuffer = combinePrivateKey3WaysAsBuffer(
      reconstructedParts['PUBLIC'],
      reconstructedParts['INSTITUTIONAL'],
      reconstructedParts['SOVEREIGN']
    );

    const signingKey = new ethers.SigningKey(keyBuffer);
    const publicKey  = signingKey.publicKey;
    const address    = ethers.computeAddress(publicKey);

    // SECURITY: Purge private key bytes from RAM immediately
    wipeBuffer(keyBuffer);
    keyBuffer = null;

    const balance = await getBalance(address);
    return { address, publicKey, balance, createdAt: createdAt.toISOString(), n, threshold };
  } finally {
    wipeBuffer(keyBuffer);
    keyBuffer = null;
    delete reconstructedParts['PUBLIC'];
    delete reconstructedParts['INSTITUTIONAL'];
    delete reconstructedParts['SOVEREIGN'];
  }
}

/**
 * CASE A — Generate Wallet
 * 1. Random Ethereum wallet
 * 2. XOR-split private key → 3 category parts
 * 3. Shamir-split each part → n shares
 * 4. Encrypt each share (AES-256-GCM) in memory
 * 5. Store each encrypted share in its own Docker container (n × 3 containers)
 * 6. DB stores ONLY: userId, category, shareIndex, n, threshold, containerId, containerName
 * 7. Private key Buffer explicitly wiped from memory with buffer.fill(0)
 */
export async function generateWallet(
  userId:         string,
  nParam?:        number,
  thresholdParam?: number
): Promise<{ address: string; publicKey: string; balance: string; n: number; threshold: number }> {
  if (await hasExistingWallet(userId)) {
    throw new Error('Wallet already exists for this user. Only one wallet generation is permitted.');
  }

  const n         = nParam         ?? env.SHARE_TOTAL_N;
  const threshold = thresholdParam ?? env.SHARE_THRESHOLD;
  validateShamirParams(n, threshold);

  const randomWallet  = ethers.Wallet.createRandom();
  const address       = randomWallet.address;
  const publicKey     = randomWallet.signingKey.publicKey;
  const rawKeyClean   = randomWallet.privateKey.startsWith('0x')
    ? randomWallet.privateKey.slice(2)
    : randomWallet.privateKey;
  const privateKeyBuf = Buffer.from(rawKeyClean, 'hex');

  try {
    const categoryParts = splitPrivateKey3Ways(privateKeyBuf);

    for (const cat of CATEGORIES) {
      const shares = splitSecret(categoryParts[cat], n, threshold);

      await Promise.all(
        shares.map(async (share, idx) => {
          const shareIndex  = idx + 1;
          const encrypted   = encryptShare(share);

          const { containerId, containerName } = await createShareContainer(
            userId, cat, shareIndex, encrypted
          );

          await prisma.keyShare.create({
            data: {
              userId,
              category:      cat,
              shareIndex,
              n,
              threshold,
              containerId,
              containerName,
            },
          });
        })
      );
    }

    const balance = await getBalance(address);
    const total   = n * CATEGORIES.length;
    console.log(
      `[walletService] Wallet created for ${userId.slice(0,8)}… — ` +
      `${total} Docker containers (${n} × ${CATEGORIES.length}). No key material in DB.`
    );

    return { address, publicKey, balance, n, threshold };
  } finally {
    // SECURITY: Scrub raw private key from RAM
    wipeBuffer(privateKeyBuf);
  }
}

/**
 * CASE B — Reconstruct Key + Execute Transaction
 * Reads shares in batch from Docker containers, reconstructs into a secure Buffer,
 * signs + broadcasts the transaction, then overwrites the buffer with zeroes immediately.
 */
export async function executeSigningTransaction(
  userId:      string,
  loginMethod: 'google' | 'mobile',
  mfaVerified: boolean,
  toAddress:   string,
  amount:      string,
  lat?:        number,
  lng?:        number
): Promise<{ txHash: string; broadcasted: boolean; message: string; explorerUrl: string }> {
  const policyCheck = await evaluateAccessPolicy(userId, loginMethod, mfaVerified, lat, lng);
  if (!policyCheck.allowed) throw new Error(`Access Denied: ${policyCheck.reason}`);

  const config = await prisma.keyShare.findFirst({
    where:  { userId },
    select: { threshold: true },
  });
  if (!config) throw new Error('Key shares not found for this user.');

  const { threshold } = config;
  let reconstructedParts: Record<string, string> = {};
  let keyBuffer: Buffer | null = null;

  try {
    reconstructedParts = await reconstructAllPartsFromContainers(userId, threshold);

    // Reconstruct directly into a zeroizable Buffer
    keyBuffer = combinePrivateKey3WaysAsBuffer(
      reconstructedParts['PUBLIC'],
      reconstructedParts['INSTITUTIONAL'],
      reconstructedParts['SOVEREIGN']
    );

    return await sendTransaction(userId, keyBuffer, toAddress, amount);
  } finally {
    // SECURITY: Ensure memory is zeroed out even if transaction throws
    wipeBuffer(keyBuffer);
    keyBuffer = null;
    delete reconstructedParts['PUBLIC'];
    delete reconstructedParts['INSTITUTIONAL'];
    delete reconstructedParts['SOVEREIGN'];
  }
}
