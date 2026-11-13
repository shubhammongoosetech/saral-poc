/**
 * sessionWalletRegistry.ts
 *
 * Ephemeral In-Memory Session Wallet Derivation & Context Registry
 *
 * Security Requirements & Guarantees:
 *  1. No public key and no wallet address may be stored in PostgreSQL, files, cookies, or JWTs.
 *  2. Wallet address and aggregated public key are regenerated (derived) on demand from the
 *     key shares held by the nodes via Lagrange interpolation in the exponent.
 *  3. In-memory session context only (Map with short TTL equal to access token lifespan).
 *  4. On logout, session expiry, or shutdown, entries are wiped from memory.
 *  5. Re-derivation is safe, fast (<15ms), and idempotent across server restarts.
 *  6. Fail-closed: If fewer than threshold nodes respond or a domain is unreachable,
 *     fails closed with an error. Never returns a fake or zero address.
 */

import crypto from 'crypto';
import { ethers } from 'ethers';
import { Keypair } from '@solana/web3.js';
import { secp256k1 } from '@noble/curves/secp256k1';
import { DomainType } from '../crypto/thresholdEcdsa';
import { computeLagrangeCoefficient } from '../crypto/shamirField';
import { nodeCluster } from './nodeClusterService';
import { getPinnedWalletPlacement } from '../topology/placement';
import { prisma } from '../config/db';
import { env } from '../config/env';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function encodeBase58(buffer: Uint8Array | Buffer): string {
  const digits: number[] = [0];
  for (let i = 0; i < buffer.length; i++) {
    for (let j = 0; j < digits.length; j++) digits[j] <<= 8;
    digits[0] += buffer[i];
    let carry = 0;
    for (let j = 0; j < digits.length; j++) {
      digits[j] += carry;
      carry = (digits[j] / 58) | 0;
      digits[j] %= 58;
    }
    while (carry) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let str = '';
  for (let i = 0; i < buffer.length && buffer[i] === 0; i++) str += '1';
  for (let i = digits.length - 1; i >= 0; i--) str += BASE58_ALPHABET[digits[i]];
  return str;
}

export function deriveSolanaKeypair(publicKeyHex: string): Keypair {
  const clean = publicKeyHex.startsWith('0x') ? publicKeyHex.slice(2) : publicKeyHex;
  const pt = secp256k1.ProjectivePoint.fromHex(clean);
  const seed = crypto
    .createHmac('sha256', 'SARAL_SOLANA_ED25519_KEY_SEED')
    .update(Buffer.from(pt.toHex(true), 'hex'))
    .digest();
  return Keypair.fromSeed(seed);
}

export function deriveSolanaAddress(publicKeyHex: string): string {
  return deriveSolanaKeypair(publicKeyHex).publicKey.toBase58();
}

export interface SessionWalletEntry {
  sessionId: string;
  userId: string;
  address: string;
  publicKey: string;
  solanaAddress: string;
  solanaKeypair?: Keypair;
  derivedAt: number;
  expiresAt: number;
  n: number;
  threshold: number;
  protocolVersion: string;
}

const SESSION_TTL_MS = (env.ACCESS_TOKEN_TTL_SECONDS || 900) * 1000; // 15 mins default
const sessionWallets = new Map<string, SessionWalletEntry>();

/**
 * Periodically purge expired sessions from memory
 */
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of sessionWallets.entries()) {
    if (entry.expiresAt <= now) {
      sessionWallets.delete(key);
    }
  }
}, 60000).unref();

/**
 * Retrieves the in-memory session wallet if active and not expired.
 */
export function getSessionWallet(key: string): SessionWalletEntry | null {
  if (!key) return null;
  const entry = sessionWallets.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    sessionWallets.delete(key);
    return null;
  }
  return entry;
}

/**
 * Stores a derived wallet in the server-side in-memory session registry.
 */
export function setSessionWallet(entry: SessionWalletEntry): void {
  sessionWallets.set(entry.userId, entry);
  if (entry.sessionId) {
    sessionWallets.set(entry.sessionId, entry);
  }
}

/**
 * Clears session wallet from memory on logout or invalidation.
 */
export function clearSessionWallet(key: string): void {
  if (!key) return;
  const existing = sessionWallets.get(key);
  if (existing) {
    sessionWallets.delete(existing.userId);
    if (existing.sessionId) {
      sessionWallets.delete(existing.sessionId);
    }
  }
  sessionWallets.delete(key);
}

/**
 * Clears all active in-memory session wallets (used during tests / shutdown).
 */
export function clearAllSessionWallets(): void {
  sessionWallets.clear();
}

/**
 * Derives the aggregated public key and Ethereum address directly from
 * public share points (s_i * G) held by the 19 distributed nodes.
 *
 * Cryptographic Protocol:
 *  1. Pinned placement identifies the assigned nodes for the user across all 3 domains.
 *  2. Required nodes compute P_i = s_i * G locally from their encrypted share.
 *  3. In each domain, Lagrange interpolation in the exponent derives Q_d = sum(lambda_i * P_i).
 *  4. Aggregated public key Q = Q_Foundation + Q_Public + Q_Private.
 *  5. Ethereum address = ethers.computeAddress(Q).
 *
 * CRITICAL SECURITY INVARIANT:
 * Master private key x is NEVER reconstructed or aggregated anywhere in memory or on disk.
 */
export async function deriveWalletFromNodes(userId: string): Promise<SessionWalletEntry> {
  const placement = await getPinnedWalletPlacement(prisma, userId);
  if (!placement) {
    throw new Error(`[SessionWallet] No pinned placement found for user ${userId}`);
  }

  const domains: DomainType[] = ['FOUNDATION', 'PUBLIC', 'PRIVATE'];
  const domainPoints = new Map<DomainType, ReturnType<typeof secp256k1.ProjectivePoint.fromHex>>();

  for (const domain of domains) {
    const domainPlacement =
      domain === 'FOUNDATION'
        ? placement.foundation
        : domain === 'PUBLIC'
        ? placement.public
        : placement.private;

    const threshold = domainPlacement.threshold;
    const assignedNodes = domainPlacement.assignedNodeIds;

    const collectedPoints: Array<{ index: number; point: ReturnType<typeof secp256k1.ProjectivePoint.fromHex>; commitments?: string[] }> = [];

    // Query nodes until threshold public points are obtained
    for (let i = 0; i < assignedNodes.length && collectedPoints.length < threshold; i++) {
      const nodeName = assignedNodes[i];
      const nodeIndex = i + 1;
      try {
        const sharePointInfo = await nodeCluster.getNodePublicSharePoint(
          userId,
          domain,
          nodeIndex,
          nodeName
        );
        const cleanHex = sharePointInfo.publicPointHex.startsWith('0x')
          ? sharePointInfo.publicPointHex.slice(2)
          : sharePointInfo.publicPointHex;
        const pt = secp256k1.ProjectivePoint.fromHex(cleanHex);
        pt.assertValidity();
        collectedPoints.push({
          index: sharePointInfo.shareIndex || nodeIndex,
          point: pt,
          commitments: sharePointInfo.commitments,
        });
      } catch (err: any) {
        // Continue to next available node in the assigned quorum
      }
    }

    if (collectedPoints.length < threshold) {
      throw new Error(
        `[SessionWallet] Derivation failed: insufficient threshold nodes available in domain ${domain}. Got ${collectedPoints.length}, required ${threshold}`
      );
    }

    // Lagrange interpolation in the exponent for this domain:
    // Q_d = sum_{i in S} lambda_i(0) * P_i
    const activeIndices = collectedPoints.map((p) => p.index);
    let domainSumPoint: ReturnType<typeof secp256k1.ProjectivePoint.fromHex> | null = null;

    for (const item of collectedPoints) {
      const lambda = computeLagrangeCoefficient(item.index, activeIndices);
      const weightedPoint = item.point.multiply(lambda);
      domainSumPoint = domainSumPoint ? domainSumPoint.add(weightedPoint) : weightedPoint;
    }

    if (!domainSumPoint) {
      throw new Error(`[SessionWallet] Failed to compute domain sum point for ${domain}`);
    }

    domainSumPoint.assertValidity();
    domainPoints.set(domain, domainSumPoint);
  }

  // Aggregate the 3 domain public key points
  const qF = domainPoints.get('FOUNDATION')!;
  const qP = domainPoints.get('PUBLIC')!;
  const qU = domainPoints.get('PRIVATE')!;

  const qAgg = qF.add(qP).add(qU);
  qAgg.assertValidity();

  const publicKey = '0x' + qAgg.toHex(false);
  const address = ethers.computeAddress(publicKey);
  const solanaKeypair = deriveSolanaKeypair(publicKey);
  const solanaAddress = solanaKeypair.publicKey.toBase58();

  const entry: SessionWalletEntry = {
    sessionId: userId,
    userId,
    address,
    publicKey,
    solanaAddress,
    solanaKeypair,
    derivedAt: Date.now(),
    expiresAt: Date.now() + SESSION_TTL_MS,
    n: placement.public.assignedNodeIds.length,
    threshold: placement.public.threshold,
    protocolVersion: 'MPC-secp256k1-v1',
  };

  setSessionWallet(entry);
  return entry;
}

/**
 * Returns the session wallet if cached in memory; otherwise securely re-derives it from nodes.
 */
export async function getOrDeriveSessionWallet(
  userId: string,
  sessionId?: string
): Promise<SessionWalletEntry> {
  const cached = getSessionWallet(sessionId || userId) || getSessionWallet(userId);
  if (cached) {
    if ((!cached.solanaKeypair || !cached.solanaAddress) && cached.publicKey) {
      cached.solanaKeypair = deriveSolanaKeypair(cached.publicKey);
      cached.solanaAddress = cached.solanaKeypair.publicKey.toBase58();
    }
    return cached;
  }
  const derived = await deriveWalletFromNodes(userId);
  if (sessionId && sessionId !== userId) {
    derived.sessionId = sessionId;
    sessionWallets.set(sessionId, derived);
  }
  return derived;
}

