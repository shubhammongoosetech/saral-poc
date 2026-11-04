/**
 * auditLogService.ts
 *
 * SARAL Cryptographic Tamper-Evident Security Audit Log Service
 *
 * Implements Merkle / Blockchain-style Hash Chaining:
 *   - Each security event log entry cryptographically commits to the SHA-256
 *     hash of the preceding entry (previousHash).
 *   - Entry Hash = SHA-256(previousHash + userId + eventType + severity + details + timestamp).
 *   - Any intermediate tampering, insertion, modification, or deletion of log records
 *     breaks the hash chain and is immediately detectable.
 *
 * Threat Model & Security Limitations:
 *   - Tamper-Evident Detection: Detects unauthorized database updates by malicious actors,
 *     compromised application processes, or SQL injection.
 *   - Administrator / Root DBA Threat: A privileged database administrator with root access
 *     could in theory recompute a modified chain from the point of alteration forward.
 *     Full immutability against root DBAs requires anchoring intermediate block hashes
 *     to an external immutable ledger or public blockchain (e.g., MST chain).
 */

import crypto from 'crypto';
import { prisma } from '../config/db';

export const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export interface SecurityEventInput {
  userId: string;
  eventType: string;
  severity?: 'INFO' | 'WARN' | 'CRITICAL' | 'SECURITY_ALERT';
  details?: Record<string, any> | string;
  ipAddress?: string;
  userAgent?: string;
}

export interface SecurityEventRecord {
  id: string;
  userId: string;
  eventType: string;
  severity: string;
  details: string;
  previousHash: string;
  entryHash: string;
  createdAt: Date;
}

/**
 * Computes deterministic SHA-256 hash of a log record
 */
export function computeLogEntryHash(
  previousHash: string,
  userId: string,
  eventType: string,
  severity: string,
  details: string,
  createdAtIso: string
): string {
  const payload = [previousHash, userId, eventType, severity, details, createdAtIso].join('|');
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Appends a tamper-evident audit record to the cryptographic hash chain
 */
export async function logSecurityEvent(
  input: SecurityEventInput
): Promise<SecurityEventRecord> {
  const detailsStr =
    typeof input.details === 'string'
      ? input.details
      : JSON.stringify(input.details || {});

  const severity = input.severity || 'INFO';

  // Retrieve the latest entry in the user's audit chain
  const lastEntry = await prisma.securityEventLog.findFirst({
    where: { userId: input.userId },
    orderBy: { createdAt: 'desc' },
    select: { entryHash: true },
  }).catch(() => null);

  const previousHash = lastEntry?.entryHash || GENESIS_HASH;
  const createdAt = new Date();
  const createdAtIso = createdAt.toISOString();

  const entryHash = computeLogEntryHash(
    previousHash,
    input.userId,
    input.eventType,
    severity,
    detailsStr,
    createdAtIso
  );

  const record = await prisma.securityEventLog.create({
    data: {
      userId: input.userId,
      eventType: input.eventType,
      severity,
      details: detailsStr,
      ipAddress: input.ipAddress || null,
      userAgent: input.userAgent || null,
      previousHash,
      entryHash,
      createdAt,
    },
  });

  return {
    id: record.id,
    userId: record.userId,
    eventType: record.eventType,
    severity: record.severity,
    details: record.details || '',
    previousHash: record.previousHash || GENESIS_HASH,
    entryHash: record.entryHash || entryHash,
    createdAt: record.createdAt,
  };
}

/**
 * Verifies the cryptographic integrity of the audit log chain for a user.
 * Returns true if intact, or false with the exact compromised record details if tampered.
 */
export async function verifyAuditChain(
  userId: string
): Promise<{ valid: boolean; totalEntries: number; tamperedEntryId?: string; reason?: string }> {
  const logs = await prisma.securityEventLog.findMany({
    where: { userId },
    orderBy: { createdAt: 'asc' },
  });

  if (logs.length === 0) {
    return { valid: true, totalEntries: 0 };
  }

  let expectedPreviousHash = GENESIS_HASH;

  for (let i = 0; i < logs.length; i++) {
    const entry = logs[i];
    const prevHash = entry.previousHash || GENESIS_HASH;

    // Check 1: Chain link linkage
    if (prevHash !== expectedPreviousHash) {
      return {
        valid: false,
        totalEntries: logs.length,
        tamperedEntryId: entry.id,
        reason: `Broken chain link at index ${i}: previousHash '${prevHash}' does not match expected '${expectedPreviousHash}'`,
      };
    }

    // Check 2: Entry hash authenticity
    const recomputedHash = computeLogEntryHash(
      prevHash,
      entry.userId,
      entry.eventType,
      entry.severity,
      entry.details || '{}',
      entry.createdAt.toISOString()
    );

    if (entry.entryHash !== recomputedHash) {
      return {
        valid: false,
        totalEntries: logs.length,
        tamperedEntryId: entry.id,
        reason: `Corrupted payload at index ${i}: entryHash '${entry.entryHash}' does not match recomputed '${recomputedHash}'`,
      };
    }

    expectedPreviousHash = entry.entryHash;
  }

  return { valid: true, totalEntries: logs.length };
}

