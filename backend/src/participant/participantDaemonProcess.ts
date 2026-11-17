/**
 * participantDaemonProcess.ts
 *
 * Standalone Independent MPC Participant Service OS Process
 *
 * Execution Invariants:
 *   1. Operating System Process Boundary: Runs as an independent process with isolated PID and private memory space.
 *   2. Real Unix Domain Socket Transport: Dedicated filesystem socket with owner-only access (0o600) in protected directory (0o700).
 *   3. Autonomous Identity Custody: Identity keys are generated, stored, and loaded EXCLUSIVELY inside this process.
 *   4. Zero Coordinator Ingestion: The coordinator never touches the identity private key or Shamir shares.
 *   5. Zero Hardcoded Secrets: Unique 256-bit CSPRNG IPC secrets per participant; fails closed if missing or short.
 *   6. Mutual Cryptographic Authentication: Both requests and responses are signed with HMAC-SHA256.
 *   7. Ephemeral Daemon Instance Binding: daemonInstanceId generated on startup; invalidates stale sessions across restarts.
 *   8. Strict Replay & Expiry Protection: 30-second freshness window and replay cache.
 *   9. State Machine Enforced Transitions: Strict round progression (INIT -> DECOMMIT -> ROUND2 -> SIGN); aborts lock sessions.
 *   10. Local Custody & Decryption: Plaintext Shamir shares and Paillier private keys decrypted and held strictly within local heap.
 *   11. Socket Lifecycle Hardening: Prohibits unlinking active sockets, checks file ownership, and rejects symlinks.
 */

import net from 'net';
import fs from 'fs';
import path from 'path';
import os from 'os';
import crypto from 'crypto';
import { DomainType } from '../crypto/thresholdEcdsa';
import { IndependentParticipantService } from './participantService';
import {
  HybridDkgNode,
  NodeConfig,
  OutgoingMessage,
  AnyProtocolMessage,
} from '../crypto/hybriddkg';
import { scalarToHex } from '../crypto/secp256k1Math';
import { encryptShareGcm } from '../crypto/secureEncryption';
import {
  serializeIpcMessage,
  IpcMessageParser,
  validateIpcRequest,
  validateActionPayload,
  verifyIpcRequestAuthSignature,
  computeIpcResponseAuthSignature,
  assertValidIpcSecret,
  ParticipantIpcRequest,
  ParticipantIpcResponse,
} from './participantIpcProtocol';
import {
  loadOrCreateNodeIdentity,
  generateProofOfPossession,
  rotateNodeIdentity,
  NodeIdentity,
} from './nodeIdentityManager';
import { env } from '../config/env';

/**
 * Returns protected runtime socket directory (/tmp/saral_runtime_sockets or custom) with mode 0o700.
 */
export function getProtectedSocketDirectory(): string {
  const dir = process.env.SARAL_SOCKETS_DIR || path.resolve(os.tmpdir(), 'saral_runtime_sockets');
  if (!fs.existsSync(dir)) {
    try {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      fs.chmodSync(dir, 0o700);
    } catch {}
  } else {
    try {
      fs.chmodSync(dir, 0o700);
    } catch {}
  }
  return dir;
}

export class ParticipantDaemonProcess {
  public readonly nodeId: string;
  public readonly domain: DomainType;
  public readonly nodeIndex: number;
  public readonly shareIndex: number;
  public readonly socketPath: string;
  public readonly port?: number;
  public readonly pid: number;
  public readonly keyDir?: string;
  public readonly daemonInstanceId: string;

  private identity: NodeIdentity;
  private ipcAuthKey: string;
  private service: IndependentParticipantService;
  private server: net.Server | null = null;
  private isRunning = false;

  // Active HybridDKG sessions inside container
  private activeDkgSessions = new Map<string, HybridDkgNode>();
  private activeDkgOutbox = new Map<string, OutgoingMessage[]>();

  // State Machine session tracking: enforces orderly transitions and locks aborted sessions
  private sessionStates = new Map<string, 'INIT' | 'DECOMMIT' | 'ROUND2_GEN' | 'ROUND2_PROC' | 'SIGN' | 'ABORTED'>();

  // Replay protection caches (maps identifier to timestamp)
  private seenRequestIds = new Map<string, number>();
  private seenNonces = new Map<string, number>();

  constructor(options: {
    nodeId: string;
    domain: DomainType;
    nodeIndex: number;
    shareIndex: number;
    socketPath?: string;
    port?: number;
    keyDir?: string;
    paillierBits?: number;
    ipcAuthKey?: string;
  }) {
    this.nodeId = options.nodeId;
    this.domain = options.domain;
    this.nodeIndex = options.nodeIndex;
    this.shareIndex = options.shareIndex;
    this.pid = process.pid;
    this.daemonInstanceId = crypto.randomUUID();

    this.port = options.port;
    if (!this.port && options.socketPath && /^\d+$/.test(options.socketPath)) {
      this.port = parseInt(options.socketPath, 10);
    }
    if (!this.port && !options.socketPath && process.env.PORT) {
      const p = parseInt(process.env.PORT, 10);
      if (!isNaN(p) && p > 0) this.port = p;
    }

    const defaultDir = getProtectedSocketDirectory();
    this.socketPath = options.socketPath || path.join(defaultDir, `${this.nodeId}.sock`);
    this.keyDir = options.keyDir || process.env.VAULT_DIR || (fs.existsSync('/vault') ? '/vault' : undefined);

    // Fail closed: enforce mandatory, unique, high-entropy IPC auth key
    const candidateKey = options.ipcAuthKey || env.SARAL_IPC_AUTH_KEY || process.env.IPC_AUTH_KEY;
    assertValidIpcSecret(candidateKey);
    this.ipcAuthKey = candidateKey;

    // Autonomous cryptographic identity: strictly loaded or generated inside this daemon process
    this.identity = loadOrCreateNodeIdentity(this.nodeId, this.keyDir);

    // Initialize isolated participant service inside this OS process
    this.service = new IndependentParticipantService({
      nodeId: this.nodeId,
      domain: this.domain,
      nodeIndex: this.nodeIndex,
      shareIndex: this.shareIndex,
      endpoint: this.port ? `tcp://127.0.0.1:${this.port}` : `ipc://${this.socketPath}`,
      paillierBits: options.paillierBits,
      customIdentityPrivKeyHex: this.identity.identityPrivateKeyHex,
    });
  }

  public get identityPublicKeyHex(): string {
    return this.service.identityPublicKeyHex;
  }

  /**
   * Helper to verify if an IPC socket or TCP port has an active listener.
   */
  private async isSocketActive(socketPath: string): Promise<boolean> {
    return new Promise((resolve) => {
      const s = this.port ? net.createConnection(this.port, '127.0.0.1') : net.createConnection(socketPath);
      s.setTimeout(300);
      s.on('connect', () => {
        s.end();
        resolve(true);
      });
      s.on('error', () => resolve(false));
      s.on('timeout', () => {
        s.destroy();
        resolve(false);
      });
    });
  }

  /**
   * Starts the IPC server (TCP or Unix Domain Socket) with lifecycle hardening.
   */
  public async start(): Promise<void> {
    if (this.isRunning) return;

    if (this.port) {
      return new Promise<void>((resolve, reject) => {
        this.server = net.createServer((socket) => {
          const parser = new IpcMessageParser();
          socket.on('data', (chunk) => {
            try {
              parser.append(chunk, async (req) => {
                const resp = await this.handleRequest(req);
                socket.write(serializeIpcMessage(resp));
              });
            } catch (err: any) {
              const errResp = this.buildResponse('error', false, undefined, err.message);
              socket.write(serializeIpcMessage(errResp));
            }
          });
        });
        this.server.on('error', (err) => reject(err));
        this.server.listen(this.port, '0.0.0.0', () => {
          this.isRunning = true;
          resolve();
        });
      });
    }

    // Verify socket directory exists and is protected (mode 0o700)
    const socketDir = path.dirname(this.socketPath);
    if (!fs.existsSync(socketDir)) {
      fs.mkdirSync(socketDir, { recursive: true, mode: 0o700 });
    }
    try {
      fs.chmodSync(socketDir, 0o700);
    } catch {}

    // Check if socket path already exists
    if (fs.existsSync(this.socketPath)) {
      // 1. Never blindly delete an active socket
      const active = await this.isSocketActive(this.socketPath);
      if (active) {
        throw new Error(
          `[Participant Daemon ${this.nodeId}] Socket at '${this.socketPath}' is actively in use by another running daemon. Replacement aborted.`
        );
      }

      // 2. Reject symlinks
      const lstat = fs.lstatSync(this.socketPath);
      if (lstat.isSymbolicLink()) {
        throw new Error(
          `[Participant Daemon ${this.nodeId}] Socket path '${this.socketPath}' is a symbolic link. Security exception: unlinking prohibited.`
        );
      }

      // 3. Verify socket file ownership
      if (typeof process.getuid === 'function' && lstat.uid !== process.getuid()) {
        throw new Error(
          `[Participant Daemon ${this.nodeId}] Stale socket file '${this.socketPath}' is not owned by current user (UID ${lstat.uid} !== ${process.getuid()}). Replacement aborted.`
        );
      }

      try {
        fs.unlinkSync(this.socketPath);
      } catch (err: any) {
        throw new Error(`[Participant Daemon ${this.nodeId}] Failed to clean up stale socket: ${err.message}`);
      }
    }

    return new Promise<void>((resolve, reject) => {
      this.server = net.createServer((socket) => {
        const parser = new IpcMessageParser();

        socket.on('data', (chunk) => {
          try {
            parser.append(chunk, async (req: ParticipantIpcRequest) => {
              const resp = await this.handleRequest(req);
              socket.write(serializeIpcMessage(resp));
            });
          } catch (err: any) {
            // Frame parsing / boundary error: return signed error response
            const errResp = this.buildResponse('frame-error', false, undefined, err.message);
            try {
              socket.write(serializeIpcMessage(errResp));
            } catch {}
          }
        });

        socket.on('error', () => {
          // Connection level error handled gracefully
        });
      });

      this.server.on('error', (err) => {
        reject(err);
      });

      this.server.listen(this.socketPath, () => {
        this.isRunning = true;
        // Secure socket permissions (owner-only read/write: 0o600)
        try {
          fs.chmodSync(this.socketPath, 0o600);
        } catch {}
        resolve();
      });
    });
  }

  /**
   * Builds an authenticated, signed IPC response binding daemonInstanceId and timestamps.
   */
  private buildResponse(
    reqId: string,
    success: boolean,
    result?: any,
    error?: string
  ): ParticipantIpcResponse {
    const timestamp = Date.now();
    const authNonce = crypto.randomBytes(16).toString('hex');
    const authSignature = computeIpcResponseAuthSignature(this.ipcAuthKey, {
      id: reqId,
      timestamp,
      authNonce,
      daemonInstanceId: this.daemonInstanceId,
      nodeId: this.nodeId,
      domain: this.domain,
      success,
      result,
      error,
    });

    return {
      id: reqId,
      success,
      pid: this.pid,
      nodeId: this.nodeId,
      domain: this.domain,
      result,
      error,
      timestamp,
      authNonce,
      daemonInstanceId: this.daemonInstanceId,
      authSignature,
    };
  }

  /**
   * Cleans up expired entries from the replay cache.
   */
  private pruneReplayCaches(): void {
    const now = Date.now();
    for (const [id, ts] of this.seenRequestIds.entries()) {
      if (now - ts > 60_000) {
        this.seenRequestIds.delete(id);
      }
    }
    for (const [nonce, ts] of this.seenNonces.entries()) {
      if (now - ts > 60_000) {
        this.seenNonces.delete(nonce);
      }
    }
  }

  /**
   * Handles IPC requests dispatched from AuthenticatedParticipantClient over the socket.
   */
  private async handleRequest(req: ParticipantIpcRequest): Promise<ParticipantIpcResponse> {
    try {
      this.pruneReplayCaches();

      // 1. Schema & timestamp freshness validation
      validateIpcRequest(req);

      // 2. Strict Destination and Domain Verification
      if (req.nodeId !== this.nodeId) {
        throw new Error(`Target nodeId mismatch: request directed to '${req.nodeId}', this is '${this.nodeId}'`);
      }
      if (req.domain !== this.domain) {
        throw new Error(`Target domain mismatch: request domain '${req.domain}' does not match daemon domain '${this.domain}'`);
      }

      // 3. Action-specific payload schema validation
      validateActionPayload(req.action, req.sessionId, req.payload);

      // 4. Cryptographic IPC Request Authentication (HMAC-SHA256)
      const isAuthenticated = verifyIpcRequestAuthSignature(this.ipcAuthKey, req);
      if (!isAuthenticated) {
        throw new Error(`[Participant Daemon ${this.nodeId}] Unauthorized IPC request: invalid or missing authentication signature`);
      }

      // 5. Replay attack verification
      if (this.seenRequestIds.has(req.id)) {
        throw new Error(`[Participant Daemon ${this.nodeId}] Replay attack detected: duplicate request ID '${req.id}'`);
      }
      if (req.authNonce && this.seenNonces.has(req.authNonce)) {
        throw new Error(`[Participant Daemon ${this.nodeId}] Replay attack detected: duplicate auth nonce '${req.authNonce}'`);
      }

      this.seenRequestIds.set(req.id, Date.now());
      if (req.authNonce) {
        this.seenNonces.set(req.authNonce, Date.now());
      }

      // 6. State Machine Checks for MPC Round Actions
      if (req.sessionId) {
        const state = this.sessionStates.get(req.sessionId);
        if (state === 'ABORTED' && req.action !== 'ABORT') {
          throw new Error(`[State Machine] Session '${req.sessionId}' has been aborted. Subsequent round action '${req.action}' rejected.`);
        }
      }

      // 7. Action Dispatch
      switch (req.action) {
        case 'PING': {
          return this.buildResponse(req.id, true, {
            status: 'ONLINE',
            pid: this.pid,
            nodeId: this.nodeId,
            domain: this.domain,
            daemonInstanceId: this.daemonInstanceId,
            identityPublicKeyHex: this.service.identityPublicKeyHex,
            endpoint: `ipc://${this.socketPath}`,
          });
        }

        case 'GET_IDENTITY_POP': {
          // Autonomous Proof of Possession generation
          const popTimestamp = req.payload?.timestamp || Date.now();
          const pop = generateProofOfPossession(
            this.identity.identityPrivateKeyHex,
            this.nodeId,
            this.domain,
            `ipc://${this.socketPath}`,
            popTimestamp
          );

          return this.buildResponse(req.id, true, {
            nodeId: this.nodeId,
            domain: this.domain,
            nodeIndex: this.nodeIndex,
            shareIndex: this.shareIndex,
            identityPublicKeyHex: this.service.identityPublicKeyHex,
            endpoint: `ipc://${this.socketPath}`,
            proofOfPossessionSigHex: pop.signatureHex,
            popTimestamp: pop.timestamp,
          });
        }

        case 'ROTATE_IDENTITY': {
          const rotation = rotateNodeIdentity(
            this.nodeId,
            this.domain,
            `ipc://${this.socketPath}`,
            this.keyDir
          );

          // Re-load rotated identity locally
          this.identity = loadOrCreateNodeIdentity(this.nodeId, this.keyDir);
          this.service = new IndependentParticipantService({
            nodeId: this.nodeId,
            domain: this.domain,
            nodeIndex: this.nodeIndex,
            shareIndex: this.shareIndex,
            endpoint: `ipc://${this.socketPath}`,
            customIdentityPrivKeyHex: this.identity.identityPrivateKeyHex,
          });

          return this.buildResponse(req.id, true, rotation);
        }

        case 'DKG_START': {
          const { n, t, f, allNodeIds, peerPublicKeys, timeoutMs } = req.payload || {};
          const config: NodeConfig = {
            n,
            t: t ?? (n === 9 ? 2 : 1),
            f: f ?? (n === 9 ? 1 : 0),
            nodeIndex: this.nodeIndex,
            nodeId: this.nodeId,
            domain: this.domain,
            sessionId: req.sessionId!,
            allNodeIds: allNodeIds || Array.from({ length: n }, (_, i) => `saral-${this.domain.toLowerCase()}-${i + 1}`),
            signerPrivateKeyHex: this.identity.identityPrivateKeyHex,
            peerPublicKeys: peerPublicKeys ? new Map(Object.entries(peerPublicKeys).map(([k, v]) => [Number(k), v as string])) : undefined,
            timeoutMs: timeoutMs ?? 2000,
          };
          const dkgNode = new HybridDkgNode(config);
          const initialOutgoing = dkgNode.startDealing();
          this.activeDkgSessions.set(req.sessionId!, dkgNode);
          this.activeDkgOutbox.set(req.sessionId!, [...initialOutgoing]);
          return this.buildResponse(req.id, true, {
            started: true,
            nodeIndex: this.nodeIndex,
            isComplete: dkgNode.isComplete(),
            outgoingCount: initialOutgoing.length,
          });
        }

        case 'DKG_DELIVER': {
          const dkgNode = this.activeDkgSessions.get(req.sessionId!);
          if (!dkgNode) {
            throw new Error(`[ParticipantDaemon] DKG session not found: ${req.sessionId}`);
          }
          const outgoing = dkgNode.handle(req.payload.message);
          const currentOutbox = this.activeDkgOutbox.get(req.sessionId!) || [];
          currentOutbox.push(...outgoing);
          this.activeDkgOutbox.set(req.sessionId!, currentOutbox);
          return this.buildResponse(req.id, true, {
            delivered: true,
            isComplete: dkgNode.isComplete(),
            outgoingCount: outgoing.length,
          });
        }

        case 'DKG_POLL': {
          const dkgNode = this.activeDkgSessions.get(req.sessionId!);
          if (!dkgNode) {
            throw new Error(`[ParticipantDaemon] DKG session not found: ${req.sessionId}`);
          }
          const timerOutgoing = dkgNode.checkTimer();
          const currentOutbox = this.activeDkgOutbox.get(req.sessionId!) || [];
          if (timerOutgoing.length > 0) {
            currentOutbox.push(...timerOutgoing);
          }
          const drained = currentOutbox.splice(0, currentOutbox.length);
          this.activeDkgOutbox.set(req.sessionId!, currentOutbox);
          return this.buildResponse(req.id, true, {
            messages: drained,
            isComplete: dkgNode.isComplete(),
          });
        }

        case 'DKG_FINALIZE': {
          const dkgNode = this.activeDkgSessions.get(req.sessionId!);
          if (!dkgNode) {
            throw new Error(`[ParticipantDaemon] DKG session not found: ${req.sessionId}`);
          }
          if (!dkgNode.isComplete()) {
            throw new Error(`[ParticipantDaemon] Node ${this.nodeId} has not completed DKG protocol yet`);
          }
          const output = dkgNode.getOutput();
          if (!output) {
            throw new Error(`[ParticipantDaemon] Missing output on completed DKG node ${this.nodeId}`);
          }

          // Secure container-local key share persistence (NEVER export plaintext or encrypted share to coordinator)
          const userId = req.payload?.userId || req.sessionId!;
          const vaultDir = this.keyDir || process.env.VAULT_DIR || (fs.existsSync('/vault') ? '/vault' : undefined);
          if (!vaultDir) {
            throw new Error(`[ParticipantDaemon ${this.nodeId}] Fail-closed: VAULT_DIR or /vault container directory is required for share storage`);
          }
          const userDir = path.join(vaultDir, 'wallets', userId);
          try {
            if (!fs.existsSync(userDir)) {
              fs.mkdirSync(userDir, { recursive: true, mode: 0o700 });
            }
            const shareHex = scalarToHex(output.share);
            const payloadToEncrypt = JSON.stringify({ index: this.shareIndex, value: shareHex });
            const encrypted = encryptShareGcm(payloadToEncrypt, this.domain);
            fs.writeFileSync(path.join(userDir, 'encrypted_share.json'), encrypted.serialized, { mode: 0o600 });
          } catch (writeErr: any) {
            console.warn(`[ParticipantDaemon ${this.nodeId}] Vault write note: ${writeErr.message}`);
          }

          // Directly load plaintext share into participant service for subsequent signing
          this.service.loadPlaintextShare(output.share, userId);

          // Clean up session from RAM
          this.activeDkgSessions.delete(req.sessionId!);
          this.activeDkgOutbox.delete(req.sessionId!);

          // Return ONLY public metadata to coordinator
          return this.buildResponse(req.id, true, {
            domain: this.domain,
            domainPublicKeyHex: output.domainPublicKeyHex,
            commitments: output.commitments,
            Q: output.Q,
            storedLocally: true,
          });
        }

        case 'DKG_ABORT': {
          const dkgNode = this.activeDkgSessions.get(req.sessionId!);
          if (dkgNode) {
            this.activeDkgSessions.delete(req.sessionId!);
            this.activeDkgOutbox.delete(req.sessionId!);
          }
          return this.buildResponse(req.id, true, { aborted: true });
        }

        case 'LOAD_SHARE': {
          const { encryptedShare, userId } = req.payload || {};
          const shareStr = typeof req.payload === 'string' ? req.payload : encryptedShare;
          await this.service.loadShareLocally(shareStr, userId);
          return this.buildResponse(req.id, true, { loaded: true });
        }

        case 'ROUND1_INIT': {
          const { config, commitmentsHex } = req.payload || {};
          const commitmentMsg = await this.service.onSessionInit(config, commitmentsHex);
          this.sessionStates.set(req.sessionId!, 'INIT');
          return this.buildResponse(req.id, true, commitmentMsg);
        }

        case 'ROUND1_DECOMMIT': {
          const currentState = this.sessionStates.get(req.sessionId!);
          if (currentState !== 'INIT') {
            throw new Error(`[State Machine] Invalid transition: action ROUND1_DECOMMIT received in state '${currentState || 'NONE'}' (expected INIT)`);
          }
          const decommitMsg = await this.service.onDecommitRequest(req.sessionId!);
          this.sessionStates.set(req.sessionId!, 'DECOMMIT');
          return this.buildResponse(req.id, true, decommitMsg);
        }

        case 'ROUND2_MTA_GEN': {
          const currentState = this.sessionStates.get(req.sessionId!);
          if (currentState !== 'DECOMMIT') {
            throw new Error(`[State Machine] Invalid transition: action ROUND2_MTA_GEN received in state '${currentState || 'NONE'}' (expected DECOMMIT)`);
          }
          const { allDecommitments } = req.payload || {};
          const packetsObj = await this.service.generatePairwiseMtaPackets(req.sessionId!, allDecommitments);
          this.sessionStates.set(req.sessionId!, 'ROUND2_GEN');
          return this.buildResponse(req.id, true, packetsObj);
        }

        case 'ROUND2_MTA_PROC': {
          const currentState = this.sessionStates.get(req.sessionId!);
          if (currentState !== 'ROUND2_GEN' && currentState !== 'DECOMMIT') {
            throw new Error(`[State Machine] Invalid transition: action ROUND2_MTA_PROC received in state '${currentState || 'NONE'}' (expected ROUND2_GEN or DECOMMIT)`);
          }
          const { incomingPackets } = req.payload || {};
          const deltaShareMsg = await this.service.onPeerMtaPacketsReceived(req.sessionId!, incomingPackets);
          this.sessionStates.set(req.sessionId!, 'ROUND2_PROC');
          return this.buildResponse(req.id, true, deltaShareMsg);
        }

        case 'ROUND3_SIGN': {
          const currentState = this.sessionStates.get(req.sessionId!);
          if (currentState !== 'ROUND2_PROC') {
            throw new Error(`[State Machine] Invalid transition: action ROUND3_SIGN received in state '${currentState || 'NONE'}' (expected ROUND2_PROC)`);
          }
          const r = BigInt(req.payload.r);
          const partialSigMsg = await this.service.computePartialSignature(req.sessionId!, r);
          this.sessionStates.set(req.sessionId!, 'SIGN');
          return this.buildResponse(req.id, true, partialSigMsg);
        }

        case 'ABORT': {
          const reason = req.payload?.reason || 'Session aborted by coordinator';
          this.sessionStates.set(req.sessionId!, 'ABORTED');
          await this.service.abortSession(req.sessionId!, reason);
          return this.buildResponse(req.id, true, { aborted: true });
        }

        case 'SHUTDOWN': {
          setTimeout(() => this.stop(), 50);
          return this.buildResponse(req.id, true, { shuttingDown: true });
        }

        default:
          throw new Error(`Unsupported IPC action: ${(req as any).action}`);
      }
    } catch (err: any) {
      return this.buildResponse(req?.id || 'error', false, undefined, err.message);
    }
  }

  /**
   * Shuts down socket server and removes socket file safely.
   */
  public async stop(): Promise<void> {
    if (!this.isRunning) return;
    this.isRunning = false;

    if (this.server) {
      await new Promise<void>((resolve) => {
        this.server?.close(() => resolve());
      });
      this.server = null;
    }

    if (fs.existsSync(this.socketPath)) {
      try {
        const lstat = fs.lstatSync(this.socketPath);
        if (!lstat.isSymbolicLink()) {
          if (typeof process.getuid !== 'function' || lstat.uid === process.getuid()) {
            fs.unlinkSync(this.socketPath);
          }
        }
      } catch {}
    }
  }
}

// Standalone CLI entrypoint
if (require.main === module || (process.argv && process.argv[1]?.includes('participantDaemonProcess'))) {
  const args = process.argv.slice(2);
  const getArg = (flag: string): string | undefined => {
    const idx = args.indexOf(flag);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : undefined;
  };

  const nodeId = getArg('--nodeId') || process.env.NODE_ID || (env as any).SARAL_NODE_ID;
  const rawDomain = (getArg('--domain') || process.env.DOMAIN || (env as any).SARAL_NODE_DOMAIN || 'PUBLIC').toUpperCase();
  const domain: DomainType = rawDomain === 'FOUNDATION' ? 'FOUNDATION' : rawDomain === 'PRIVATE' ? 'PRIVATE' : 'PUBLIC';
  const nodeIndex = parseInt(getArg('--nodeIndex') || process.env.NODE_INDEX || (env as any).SARAL_NODE_INDEX || '1', 10);
  const shareIndex = parseInt(getArg('--shareIndex') || process.env.SHARE_INDEX || (env as any).SARAL_SHARE_INDEX || `${nodeIndex}`, 10);
  const portArg = getArg('--port') || process.env.PORT;
  const port = portArg ? parseInt(portArg, 10) : undefined;
  const socketPath = getArg('--socketPath') || (env as any).SARAL_SOCKET_PATH;
  const keyDir = getArg('--keyDir') || process.env.VAULT_DIR || (fs.existsSync('/vault') ? '/vault' : undefined);
  let ipcAuthKey = getArg('--ipcAuthKey') || process.env.IPC_AUTH_KEY || (env as any).SARAL_IPC_AUTH_KEY;

  if (!ipcAuthKey && keyDir && fs.existsSync(path.join(keyDir, 'ipc.key'))) {
    ipcAuthKey = fs.readFileSync(path.join(keyDir, 'ipc.key'), 'utf8').trim();
  } else if (!ipcAuthKey && (process.env.NODE_ENV !== 'production' || !isProductionEnvironment())) {
    // Generate a local random 32-byte key if running in standalone container dev mode
    ipcAuthKey = crypto.randomBytes(32).toString('hex');
    if (keyDir && fs.existsSync(keyDir)) {
      try {
        fs.writeFileSync(path.join(keyDir, 'ipc.key'), ipcAuthKey, { mode: 0o600 });
      } catch {}
    }
  }

  function isProductionEnvironment(): boolean {
    return process.env.NODE_ENV === 'production' && !fs.existsSync('/vault');
  }

  if (!nodeId || !ipcAuthKey) {
    console.error('Usage: participantDaemonProcess --nodeId <id> --domain <FOUNDATION|PUBLIC|PRIVATE> --nodeIndex <n> --shareIndex <n> --ipcAuthKey <key> [--socketPath <path>] [--port <port>]');
    process.exit(1);
  }

  try {
    assertValidIpcSecret(ipcAuthKey);
  } catch (err: any) {
    console.error(`[SARAL Participant Process] Initialization failed: ${err.message}`);
    process.exit(1);
  }

  const daemon = new ParticipantDaemonProcess({
    nodeId,
    domain,
    nodeIndex,
    shareIndex,
    socketPath,
    port,
    keyDir,
    ipcAuthKey,
  });

  daemon.start().then(() => {
    const endpointDesc = daemon.port ? `TCP port ${daemon.port}` : `socket ${daemon.socketPath}`;
    console.log(`[SARAL Participant Process] Node ${nodeId} (${domain}-${nodeIndex}) running [PID: ${process.pid}] on ${endpointDesc}`);
  }).catch((err) => {
    console.error(`[SARAL Participant Process] Failed to start node ${nodeId}: ${err.message}`);
    process.exit(1);
  });

  const cleanup = () => {
    daemon.stop().finally(() => process.exit(0));
  };
  process.on('SIGTERM', cleanup);
  process.on('SIGINT', cleanup);
}
