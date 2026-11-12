/**
 * participantClient.ts
 *
 * Authenticated Network / Unix Domain Socket RPC Client for Independent MPC Participants
 *
 * Security Invariants:
 *   1. Zero Process Memory Leakage: Holds strictly transport endpoint metadata; ZERO service instances in memory.
 *   2. Zero Plaintext Secret Material: Holds ZERO private Shamir shares, zero nonces, and zero Paillier secret keys.
 *   3. Genuine IPC Process Boundary: Communicates exclusively across Unix domain sockets with standalone OS processes.
 *   4. Zero Hardcoded Secrets: Unique CSPRNG IPC secrets per participant; fails closed if missing or short (< 32 chars).
 *   5. Mutual Cryptographic Authentication: Validates HMAC-SHA256 signature on all incoming responses from the daemon.
 *   6. Strict ID, Node, Domain & Freshness Binding: Enforces request/response ID matching, nodeId matching, domain matching, and freshness window.
 *   7. Daemon Instance Restart Protection: Invalidate active sessions if daemonInstanceId changes.
 */

import net from 'net';
import path from 'path';
import crypto from 'crypto';
import { DomainType } from '../crypto/thresholdEcdsa';
import {
  ParticipantId,
  MpcSessionConfig,
  Round1CommitmentMessage,
  Round1DecommitmentMessage,
  Round2PairwiseMtaPacket,
  Round2DeltaShareMessage,
  Round3PartialSignatureMessage,
} from '../crypto/mpcProtocolTypes';
import { IMpcParticipantClient } from './participantTransport';
import { env } from '../config/env';
import {
  serializeIpcMessage,
  IpcMessageParser,
  computeIpcRequestAuthSignature,
  verifyIpcResponseAuthSignature,
  assertValidIpcSecret,
  ParticipantIpcAction,
  ParticipantIpcRequest,
  ParticipantIpcResponse,
} from './participantIpcProtocol';
import { getProtectedSocketDirectory } from './participantDaemonProcess';

export class AuthenticatedParticipantClient implements IMpcParticipantClient {
  public readonly id: ParticipantId;
  public readonly domain: DomainType;
  public readonly nodeIndex: number;
  public readonly shareIndex: number;
  public readonly identityPublicKeyHex: string;
  public readonly endpoint: string;
  public readonly socketPath: string;
  public readonly remotePid?: number;
  private readonly ipcAuthKey: string;
  private currentDaemonInstanceId?: string;

  constructor(options: {
    id: ParticipantId;
    domain: DomainType;
    nodeIndex: number;
    shareIndex: number;
    identityPublicKeyHex: string;
    socketPath?: string;
    endpoint?: string;
    remotePid?: number;
    ipcAuthKey?: string;
  }) {
    this.id = options.id;
    this.domain = options.domain;
    this.nodeIndex = options.nodeIndex;
    this.shareIndex = options.shareIndex;
    this.identityPublicKeyHex = options.identityPublicKeyHex;
    
    const defaultSocket = path.join(getProtectedSocketDirectory(), `${options.id}.sock`);
    this.endpoint = options.endpoint || (options.socketPath ? `ipc://${options.socketPath}` : `ipc://${defaultSocket}`);
    this.socketPath = options.socketPath || this.endpoint.replace('ipc://', '');
    this.remotePid = options.remotePid;

    // Fail closed: enforce mandatory, unique, high-entropy IPC auth key
    const candidateKey = options.ipcAuthKey || env.SARAL_IPC_AUTH_KEY;
    assertValidIpcSecret(candidateKey);
    this.ipcAuthKey = candidateKey;
  }

  /**
   * Resets or sets the tracked daemonInstanceId (used in restart testing).
   */
  public setTrackedDaemonInstanceId(instanceId?: string): void {
    this.currentDaemonInstanceId = instanceId;
  }

  /**
   * Dispatches an authenticated request over the Unix domain socket to the isolated participant daemon.
   * Performs mutual cryptographic response verification before returning results.
   */
  public async sendIpcRequest<T>(
    action: ParticipantIpcAction,
    sessionId?: string,
    payload?: any,
    timeoutMs: number = 30_000,
    overrideAuth?: {
      invalidSig?: boolean;
      expiredTimestamp?: number;
      customNonce?: string;
      customNodeId?: string;
      customDomain?: DomainType;
    }
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const socket = net.createConnection(this.socketPath);
      const parser = new IpcMessageParser();
      let settled = false;
      let currentReqId = '';

      const timer = setTimeout(() => {
        if (!settled) {
          settled = true;
          socket.destroy();
          reject(
            new Error(
              `[IPC Client ${this.id}] Timeout after ${timeoutMs}ms waiting for action '${action}' on socket '${this.socketPath}'`
            )
          );
        }
      }, timeoutMs);

      socket.on('connect', () => {
        currentReqId = `req-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
        const reqId = currentReqId;
        const ts = overrideAuth?.expiredTimestamp !== undefined ? overrideAuth.expiredTimestamp : Date.now();
        const authNonce = overrideAuth?.customNonce || crypto.randomBytes(16).toString('hex');
        const targetNodeId = overrideAuth?.customNodeId || this.id;
        const targetDomain = overrideAuth?.customDomain || this.domain;

        let authSignature = computeIpcRequestAuthSignature(this.ipcAuthKey, {
          action,
          id: reqId,
          timestamp: ts,
          authNonce,
          nodeId: targetNodeId,
          domain: targetDomain,
          sessionId,
          payload,
        });

        if (overrideAuth?.invalidSig) {
          authSignature = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
        }

        const req: ParticipantIpcRequest = {
          id: reqId,
          action,
          sessionId,
          nodeId: targetNodeId,
          domain: targetDomain,
          payload,
          timestamp: ts,
          authNonce,
          authSignature,
        };

        socket.write(serializeIpcMessage(req));
      });

      socket.on('data', (chunk) => {
        try {
          parser.append(chunk, (resp: ParticipantIpcResponse) => {
            if (!settled) {
              settled = true;
              clearTimeout(timer);
              socket.end();

              // 1. Response ID Binding Check
              if (resp.id !== 'frame-error' && resp.id !== currentReqId) {
                return reject(
                  new Error(
                    `[IPC Client ${this.id}] Response ID substitution detected: expected '${currentReqId}', received '${resp.id}'`
                  )
                );
              }

              // 2. Node ID Binding Check
              if (resp.nodeId !== this.id) {
                return reject(
                  new Error(
                    `[IPC Client ${this.id}] Target nodeId mismatch: response from '${resp.nodeId}', expected '${this.id}'`
                  )
                );
              }

              // 3. Domain Binding Check
              if (resp.domain !== this.domain) {
                return reject(
                  new Error(
                    `[IPC Client ${this.id}] Target domain mismatch: response domain '${resp.domain}' does not match expected '${this.domain}'`
                  )
                );
              }

              // 4. Response Freshness Window (30 seconds)
              if (Math.abs(Date.now() - resp.timestamp) > 30_000) {
                return reject(
                  new Error(
                    `[IPC Client ${this.id}] Security Exception: Response expired or clock skew exceeded 30s`
                  )
                );
              }

              // 5. Cryptographic Mutual Response Verification (HMAC-SHA256)
              const isValidSig = verifyIpcResponseAuthSignature(this.ipcAuthKey, resp);
              if (!isValidSig) {
                return reject(
                  new Error(
                    `[IPC Client ${this.id}] Security Exception: Cryptographic response verification failed: invalid HMAC-SHA256 signature for action '${action}'`
                  )
                );
              }

              // 6. Ephemeral Daemon Instance Binding & Restart Invalidation
              if (this.currentDaemonInstanceId && this.currentDaemonInstanceId !== resp.daemonInstanceId) {
                return reject(
                  new Error(
                    `[IPC Client ${this.id}] Security Exception: Daemon restart detected: instance changed from '${this.currentDaemonInstanceId}' to '${resp.daemonInstanceId}'. Active session invalidated.`
                  )
                );
              }
              this.currentDaemonInstanceId = resp.daemonInstanceId;

              // 7. Result Dispatch
              if (!resp.success) {
                reject(
                  new Error(
                    `[Participant Daemon ${this.id}] ${action} failed: ${resp.error || 'Unknown error'}`
                  )
                );
              } else {
                resolve(resp.result as T);
              }
            }
          });
        } catch (err: any) {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            socket.destroy();
            reject(err);
          }
        }
      });

      socket.on('error', (err) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          reject(
            new Error(
              `[IPC Client ${this.id}] Socket connection failed to ${this.socketPath}: ${err.message}`
            )
          );
        }
      });
    });
  }

  public async ping(): Promise<{ status: string; pid: number; identityPublicKeyHex: string; daemonInstanceId: string }> {
    return this.sendIpcRequest('PING');
  }

  /**
   * Retrieves autonomous identity and Proof of Possession from the daemon process.
   */
  public async getIdentityPoP(timestamp?: number): Promise<{
    nodeId: string;
    domain: DomainType;
    nodeIndex: number;
    shareIndex: number;
    identityPublicKeyHex: string;
    endpoint: string;
    proofOfPossessionSigHex: string;
    popTimestamp: number;
  }> {
    return this.sendIpcRequest('GET_IDENTITY_POP', undefined, { timestamp });
  }

  /**
   * Requests autonomous identity rotation inside the daemon process.
   */
  public async rotateIdentity(): Promise<{
    oldPublicKeyHex: string;
    newPublicKeyHex: string;
    proofOfPossessionSigHex: string;
    popTimestamp: number;
  }> {
    return this.sendIpcRequest('ROTATE_IDENTITY');
  }

  public async loadShare(encryptedShare: string | { serialized?: string; encryptedShare?: string; userId?: string } | any): Promise<{ loaded: boolean }> {
    let encStr = '';
    let userId: string | undefined;

    if (typeof encryptedShare === 'string') {
      encStr = encryptedShare;
    } else if (encryptedShare && typeof encryptedShare === 'object') {
      encStr = encryptedShare.encryptedShare || encryptedShare.serialized || JSON.stringify(encryptedShare);
      userId = encryptedShare.userId;
    } else {
      encStr = String(encryptedShare);
    }
    return this.sendIpcRequest('LOAD_SHARE', undefined, { encryptedShare: encStr, userId });
  }

  public async initSession(
    config: MpcSessionConfig,
    commitmentsHex?: string[]
  ): Promise<Round1CommitmentMessage> {
    return this.sendIpcRequest('ROUND1_INIT', config.sessionId, { config, commitmentsHex });
  }

  public async decommit(sessionId: string): Promise<Round1DecommitmentMessage> {
    return this.sendIpcRequest('ROUND1_DECOMMIT', sessionId);
  }

  public async generateMtaPackets(
    sessionId: string,
    allDecommitments: Round1DecommitmentMessage[]
  ): Promise<{ packets: Round2PairwiseMtaPacket[] }> {
    return this.sendIpcRequest('ROUND2_MTA_GEN', sessionId, { allDecommitments });
  }

  public async processMtaPackets(
    sessionId: string,
    incomingPackets: Round2PairwiseMtaPacket[]
  ): Promise<Round2DeltaShareMessage> {
    return this.sendIpcRequest('ROUND2_MTA_PROC', sessionId, { incomingPackets });
  }

  public async computePartialSignature(
    sessionId: string,
    r: bigint
  ): Promise<Round3PartialSignatureMessage> {
    return this.sendIpcRequest('ROUND3_SIGN', sessionId, { r: '0x' + r.toString(16) });
  }

  public async abortSession(sessionId: string, reason: string): Promise<void> {
    await this.sendIpcRequest('ABORT', sessionId, { reason });
  }

  // ── Backward-Compatibility Aliases (Duck-typing for MpcParticipantDaemon) ──
  public async onSessionInit(
    config: MpcSessionConfig,
    commitmentsHex?: string[]
  ): Promise<Round1CommitmentMessage> {
    return this.initSession(config, commitmentsHex);
  }

  public async onDecommitRequest(sessionId: string): Promise<Round1DecommitmentMessage> {
    return this.decommit(sessionId);
  }

  public async onPeerMtaPacketsReceived(
    sessionId: string,
    incomingPackets: Round2PairwiseMtaPacket[]
  ): Promise<Round2DeltaShareMessage> {
    return this.processMtaPackets(sessionId, incomingPackets);
  }
}
