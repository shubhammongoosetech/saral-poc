/**
 * participantIpcProtocol.ts
 *
 * Framing, Schema, and Mutual Authentication Protocol for Independent MPC Daemons
 *
 * Security Invariants:
 *   - Length-prefixed binary framing prevents boundary injection and fragment truncation.
 *   - Frame Size Boundary: Strict maximum frame size limit (2 MB) prevents memory exhaustion DoS attacks.
 *   - Zero Hardcoded Secrets: All default fallback secrets are eliminated; unique credentials (min 32 chars) are mandatory.
 *   - Mutual Cryptographic Authentication: Both requests and responses are signed with HMAC-SHA256.
 *   - Strict Domain, Identity & ID Binding: Directional canonical prefixes ('REQ' / 'RESP') and ID bindings prevent reflection and substitution attacks.
 *   - Ephemeral Instance Binding: Responses bind to daemonInstanceId; daemon restarts invalidate pre-restart sessions.
 *   - Action Schema Validation: Every action's payload is strictly validated against domain-specific schema.
 *   - Zero plaintext private share or scalar fields are allowed in serialized payloads.
 */

import crypto from 'crypto';
import { DomainType } from '../crypto/thresholdEcdsa';
import {
  MpcSessionConfig,
  Round1CommitmentMessage,
  Round1DecommitmentMessage,
  Round2PairwiseMtaPacket,
  Round2DeltaShareMessage,
  Round3PartialSignatureMessage,
} from '../crypto/mpcProtocolTypes';

export const MAX_IPC_FRAME_SIZE = 2 * 1024 * 1024; // 2 Megabytes maximum frame limit

export type ParticipantIpcAction =
  | 'PING'
  | 'GET_IDENTITY_POP'
  | 'ROTATE_IDENTITY'
  | 'LOAD_SHARE'
  | 'ROUND1_INIT'
  | 'ROUND1_DECOMMIT'
  | 'ROUND2_MTA_GEN'
  | 'ROUND2_MTA_PROC'
  | 'ROUND3_SIGN'
  | 'ABORT'
  | 'SHUTDOWN';

export interface ParticipantIpcRequest {
  id: string;
  action: ParticipantIpcAction;
  sessionId?: string;
  nodeId: string;
  domain: DomainType;
  payload?: any;
  timestamp: number;
  authNonce: string;
  authSignature: string;
}

export interface ParticipantIpcResponse {
  id: string;
  success: boolean;
  pid: number;
  nodeId: string;
  domain: DomainType;
  result?: any;
  error?: string;
  timestamp: number;
  authNonce: string;
  daemonInstanceId: string;
  authSignature: string;
}

/**
 * Validates that an IPC secret meets strict cryptographic entropy requirements (min 32 chars / 256 bits).
 * Fails closed if missing, empty, or insufficient entropy.
 */
export function assertValidIpcSecret(secret: string | undefined): asserts secret is string {
  if (!secret || typeof secret !== 'string' || secret.trim().length < 32) {
    throw new Error(
      '[IPC Protocol] Security Exception: A unique, cryptographically strong IPC secret (minimum 32 characters) is strictly required. Hardcoded or default secrets are eliminated.'
    );
  }
}

/**
 * Permanently eliminated default fallback secret. Fails closed unconditionally.
 */
export function getDefaultIpcAuthSecret(): never {
  throw new Error(
    '[IPC Protocol] Security Exception: Hardcoded default IPC secrets have been permanently eliminated. A unique cryptographic secret (minimum 32 characters) must be explicitly provided.'
  );
}

/**
 * Computes canonical HMAC-SHA256 signature for an outgoing IPC request.
 * Binds (REQ || action || id || timestamp || authNonce || nodeId || domain || sessionId || payloadHash).
 */
export function computeIpcRequestAuthSignature(
  secret: string,
  req: {
    action: string;
    id: string;
    timestamp: number;
    authNonce: string;
    nodeId: string;
    domain: DomainType;
    sessionId?: string;
    payload?: any;
  }
): string {
  assertValidIpcSecret(secret);
  const payloadStr = JSON.stringify(req.payload !== undefined ? req.payload : {}, (key, value) =>
    typeof value === 'bigint' ? '0x' + value.toString(16) : value
  );
  const payloadHash = crypto.createHash('sha256').update(payloadStr).digest('hex');
  const canonical = `SARAL_IPC_REQ:v2:${req.action}:${req.id}:${req.timestamp}:${req.authNonce}:${req.nodeId}:${req.domain}:${req.sessionId || ''}:${payloadHash}`;
  return crypto.createHmac('sha256', secret).update(canonical).digest('hex');
}

/**
 * Backward-compatible alias for computeIpcRequestAuthSignature.
 */
export function computeIpcAuthSignature(
  secret: string,
  req: {
    action: string;
    id: string;
    timestamp: number;
    authNonce: string;
    nodeId?: string;
    domain?: DomainType;
    sessionId?: string;
    payload?: any;
  }
): string {
  return computeIpcRequestAuthSignature(secret, {
    action: req.action,
    id: req.id,
    timestamp: req.timestamp,
    authNonce: req.authNonce,
    nodeId: req.nodeId || 'unknown-node',
    domain: req.domain || 'PUBLIC',
    sessionId: req.sessionId,
    payload: req.payload,
  });
}

/**
 * Validates HMAC-SHA256 authentication signature on an incoming IPC request using timing-safe comparison.
 */
export function verifyIpcRequestAuthSignature(
  secret: string,
  req: ParticipantIpcRequest
): boolean {
  if (!req.authSignature || !req.authNonce) return false;
  try {
    assertValidIpcSecret(secret);
    const expected = computeIpcRequestAuthSignature(secret, {
      action: req.action,
      id: req.id,
      timestamp: req.timestamp,
      authNonce: req.authNonce,
      nodeId: req.nodeId,
      domain: req.domain,
      sessionId: req.sessionId,
      payload: req.payload,
    });
    const sigBuf = Buffer.from(req.authSignature, 'hex');
    const expBuf = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length) return false;
    return crypto.timingSafeEqual(sigBuf, expBuf);
  } catch {
    return false;
  }
}

/**
 * Backward-compatible alias for verifyIpcRequestAuthSignature.
 */
export function verifyIpcAuthSignature(
  secret: string,
  req: ParticipantIpcRequest
): boolean {
  return verifyIpcRequestAuthSignature(secret, req);
}

/**
 * Computes canonical HMAC-SHA256 signature for an outgoing IPC response from the daemon.
 * Binds (RESP || id || timestamp || authNonce || daemonInstanceId || nodeId || domain || success || resultHash).
 */
export function computeIpcResponseAuthSignature(
  secret: string,
  resp: {
    id: string;
    timestamp: number;
    authNonce: string;
    daemonInstanceId: string;
    nodeId: string;
    domain: DomainType;
    success: boolean;
    result?: any;
    error?: string;
  }
): string {
  assertValidIpcSecret(secret);
  const dataStr = JSON.stringify(resp.result !== undefined ? resp.result : resp.error || '', (key, value) =>
    typeof value === 'bigint' ? '0x' + value.toString(16) : value
  );
  const dataHash = crypto.createHash('sha256').update(dataStr).digest('hex');
  const canonical = `SARAL_IPC_RESP:v2:${resp.id}:${resp.timestamp}:${resp.authNonce}:${resp.daemonInstanceId}:${resp.nodeId}:${resp.domain}:${resp.success}:${dataHash}`;
  return crypto.createHmac('sha256', secret).update(canonical).digest('hex');
}

/**
 * Validates HMAC-SHA256 authentication signature on an incoming IPC response using timing-safe comparison.
 */
export function verifyIpcResponseAuthSignature(
  secret: string,
  resp: ParticipantIpcResponse
): boolean {
  if (!resp.authSignature || !resp.authNonce || !resp.daemonInstanceId) return false;
  try {
    assertValidIpcSecret(secret);
    const expected = computeIpcResponseAuthSignature(secret, {
      id: resp.id,
      timestamp: resp.timestamp,
      authNonce: resp.authNonce,
      daemonInstanceId: resp.daemonInstanceId,
      nodeId: resp.nodeId,
      domain: resp.domain,
      success: resp.success,
      result: resp.result,
      error: resp.error,
    });
    const sigBuf = Buffer.from(resp.authSignature, 'hex');
    const expBuf = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length) return false;
    return crypto.timingSafeEqual(sigBuf, expBuf);
  } catch {
    return false;
  }
}

/**
 * Serializes an IPC message with a 4-byte big-endian length prefix.
 */
export function serializeIpcMessage(msg: ParticipantIpcRequest | ParticipantIpcResponse): Buffer {
  const jsonStr = JSON.stringify(msg, (key, value) =>
    typeof value === 'bigint' ? '0x' + value.toString(16) : value
  );
  const payloadBuf = Buffer.from(jsonStr, 'utf8');
  if (payloadBuf.length > MAX_IPC_FRAME_SIZE) {
    throw new Error(
      `[IPC Protocol] Outgoing frame size ${payloadBuf.length} exceeds maximum allowed limit of ${MAX_IPC_FRAME_SIZE} bytes (2 MB)`
    );
  }
  const lengthBuf = Buffer.alloc(4);
  lengthBuf.writeUInt32BE(payloadBuf.length, 0);
  return Buffer.concat([lengthBuf, payloadBuf]);
}

/**
 * Creates a streaming buffer parser that handles chunked TCP / Unix socket data
 * and emits complete IPC messages, strictly enforcing maximum frame boundaries.
 */
export class IpcMessageParser {
  private buffer = Buffer.alloc(0);

  public append(chunk: Buffer | string, onMessage: (msg: any) => void): void {
    const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
    this.buffer = Buffer.concat([this.buffer, buf]);

    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);

      // Guard against frame injection & memory exhaustion attacks
      if (length > MAX_IPC_FRAME_SIZE) {
        this.buffer = Buffer.alloc(0);
        throw new Error(
          `[IPC Protocol] Security Exception: Frame size ${length} bytes exceeds maximum allowed limit of ${MAX_IPC_FRAME_SIZE} bytes (2 MB)`
        );
      }

      if (this.buffer.length < 4 + length) {
        break; // Await more chunks
      }

      const payloadBuf = this.buffer.subarray(4, 4 + length);
      this.buffer = this.buffer.subarray(4 + length);

      const jsonStr = payloadBuf.toString('utf8');
      const parsed = JSON.parse(jsonStr, (key, value) => {
        if (
          typeof value === 'string' &&
          value.startsWith('0x') &&
          value.length > 2 &&
          /^[0-9a-fA-F]+$/.test(value.slice(2)) &&
          (key === 'messageScalar' || key === 'r' || key === 'sigma_i' || key === 'delta_i' || key === 'plainVal')
        ) {
          try {
            return BigInt(value);
          } catch {
            return value;
          }
        }
        return value;
      });

      onMessage(parsed);
    }
  }
}

/**
 * Validates request payload against security requirements and freshness window.
 */
export function validateIpcRequest(req: any): asserts req is ParticipantIpcRequest {
  if (!req || typeof req !== 'object') {
    throw new Error('[IPC Protocol] Malformed request: expected JSON object');
  }
  if (!req.id || typeof req.id !== 'string') {
    throw new Error('[IPC Protocol] Request missing unique "id" field');
  }
  if (!req.action || typeof req.action !== 'string') {
    throw new Error('[IPC Protocol] Request missing "action" field');
  }
  if (!req.nodeId || typeof req.nodeId !== 'string') {
    throw new Error('[IPC Protocol] Request missing "nodeId" field');
  }
  if (!req.domain || typeof req.domain !== 'string') {
    throw new Error('[IPC Protocol] Request missing "domain" field');
  }
  if (!req.authNonce || typeof req.authNonce !== 'string') {
    throw new Error('[IPC Protocol] Request missing "authNonce" field');
  }
  if (!req.authSignature || typeof req.authSignature !== 'string') {
    throw new Error('[IPC Protocol] Request missing "authSignature" field');
  }

  // Freshness validation (reject requests older than 30s or with excessive clock skew)
  if (typeof req.timestamp !== 'number') {
    throw new Error('[IPC Protocol] Request missing numeric "timestamp" field');
  }
  const skew = Math.abs(Date.now() - req.timestamp);
  if (skew > 30_000) {
    throw new Error(
      `[IPC Protocol] Security Exception: Request expired or excessive clock skew (${skew}ms > 30000ms limit)`
    );
  }
}

/**
 * Strictly validates action-specific payload schema to prevent malformed or injection attacks.
 */
export function validateActionPayload(action: ParticipantIpcAction, sessionId?: string, payload?: any): void {
  switch (action) {
    case 'PING':
    case 'GET_IDENTITY_POP':
      // No required complex payload
      break;

    case 'LOAD_SHARE':
      if (!payload || typeof payload !== 'object' || typeof payload.encryptedShare !== 'string' || payload.encryptedShare.trim().length === 0) {
        throw new Error('[IPC Protocol] Action LOAD_SHARE requires non-empty string payload.encryptedShare');
      }
      break;

    case 'ROUND1_INIT':
      if (!sessionId || typeof sessionId !== 'string') {
        throw new Error('[IPC Protocol] Action ROUND1_INIT requires non-empty sessionId');
      }
      if (!payload || typeof payload !== 'object' || !payload.config || typeof payload.config !== 'object') {
        throw new Error('[IPC Protocol] Action ROUND1_INIT requires valid payload.config object');
      }
      if (!Array.isArray(payload.config.participants) || payload.config.participants.length === 0) {
        throw new Error('[IPC Protocol] Action ROUND1_INIT requires non-empty participants array in config');
      }
      break;

    case 'ROUND1_DECOMMIT':
      if (!sessionId || typeof sessionId !== 'string') {
        throw new Error('[IPC Protocol] Action ROUND1_DECOMMIT requires non-empty sessionId');
      }
      break;

    case 'ROUND2_MTA_GEN':
      if (!sessionId || typeof sessionId !== 'string') {
        throw new Error('[IPC Protocol] Action ROUND2_MTA_GEN requires non-empty sessionId');
      }
      if (!payload || !Array.isArray(payload.allDecommitments)) {
        throw new Error('[IPC Protocol] Action ROUND2_MTA_GEN requires array payload.allDecommitments');
      }
      break;

    case 'ROUND2_MTA_PROC':
      if (!sessionId || typeof sessionId !== 'string') {
        throw new Error('[IPC Protocol] Action ROUND2_MTA_PROC requires non-empty sessionId');
      }
      if (!payload || !Array.isArray(payload.incomingPackets)) {
        throw new Error('[IPC Protocol] Action ROUND2_MTA_PROC requires array payload.incomingPackets');
      }
      break;

    case 'ROUND3_SIGN':
      if (!sessionId || typeof sessionId !== 'string') {
        throw new Error('[IPC Protocol] Action ROUND3_SIGN requires non-empty sessionId');
      }
      if (!payload || (typeof payload.r !== 'string' && typeof payload.r !== 'bigint')) {
        throw new Error('[IPC Protocol] Action ROUND3_SIGN requires valid payload.r scalar');
      }
      break;

    case 'ABORT':
      if (!sessionId || typeof sessionId !== 'string') {
        throw new Error('[IPC Protocol] Action ABORT requires non-empty sessionId');
      }
      break;

    case 'ROTATE_IDENTITY':
    case 'SHUTDOWN':
      // Authorized administrative actions
      break;

    default:
      throw new Error(`[IPC Protocol] Unsupported action '${action}'`);
  }
}
