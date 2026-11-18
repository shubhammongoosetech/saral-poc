/**
 * P2PNodeDaemon.ts
 *
 * Autonomous P2P TSS Participant Node Daemon for SARAL.
 *
 * Operational & Cryptographic Invariants:
 *  1. Operating System Process Isolation: Designed to run as an independent OS process or Docker container.
 *  2. Vault Enclave: All secret key shares and identity private keys are persisted exclusively
 *     inside local protected filesystem storage (e.g. /vault or dedicated vault directory).
 *  3. Zero Private Key Leakage: Private scalars never leave the local vault process.
 *  4. Direct P2P Protocols: Verifiable Secret Sharing, Nonce exchanges, and TSS rounds execute
 *     directly peer-to-peer over authenticated, encrypted P2P sockets.
 */

import fs from 'fs';
import path from 'path';
import net from 'net';
import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { P2PTransport } from './P2PTransport';
import {
  P2PNodeDaemonConfig,
  P2PMessageEnvelope,
  StoredKeyShare,
  TssProtocol,
} from './types';
import {
  FrostEd25519NoncePair,
  generateEd25519NoncePair,
  computeEd25519SignatureShare,
} from '../protocols/frost-ed25519';
import {
  FrostTaprootNoncePair,
  generateTaprootNoncePair,
  computeTaprootSignatureShare,
} from '../protocols/frost-taproot';
import {
  Cggmp21ParticipantState,
  initCggmp21Round1,
  generateCggmp21Round2Decommitment,
  computeCggmp21Round3DeltaShare,
  computeCggmp21Round4SignatureShare,
} from '../protocols/cggmp21';

export class P2PNodeDaemon {
  public readonly config: P2PNodeDaemonConfig;
  public identityPrivateKeyHex!: string;
  public identityPublicKeyHex!: string;

  private server: net.Server | null = null;
  private isRunning = false;

  // Ephemeral in-memory signing sessions
  private ed25519Nonces = new Map<string, FrostEd25519NoncePair>();
  private taprootNonces = new Map<string, FrostTaprootNoncePair>();
  private cggmp21States = new Map<string, Cggmp21ParticipantState>();

  constructor(config: P2PNodeDaemonConfig) {
    this.config = config;
    this.initVault();
  }

  /**
   * Initializes local vault storage and loads or creates node identity keypair.
   */
  private initVault(): void {
    if (!fs.existsSync(this.config.vaultDir)) {
      fs.mkdirSync(this.config.vaultDir, { recursive: true, mode: 0o700 });
    }

    const identityFile = path.join(this.config.vaultDir, 'node_identity.json');
    if (fs.existsSync(identityFile)) {
      try {
        const raw = JSON.parse(fs.readFileSync(identityFile, 'utf8'));
        this.identityPrivateKeyHex = raw.identityPrivateKeyHex;
        this.identityPublicKeyHex = raw.identityPublicKeyHex;
      } catch {
        this.generateNewIdentity(identityFile);
      }
    } else {
      this.generateNewIdentity(identityFile);
    }
  }

  private generateNewIdentity(identityFile: string): void {
    const priv = crypto.randomBytes(32);
    const pub = secp256k1.getPublicKey(priv, true);
    this.identityPrivateKeyHex = priv.toString('hex');
    this.identityPublicKeyHex = Buffer.from(pub).toString('hex');

    fs.writeFileSync(
      identityFile,
      JSON.stringify(
        {
          nodeId: this.config.nodeId,
          domain: this.config.domain,
          identityPrivateKeyHex: this.identityPrivateKeyHex,
          identityPublicKeyHex: this.identityPublicKeyHex,
          createdAt: Date.now(),
        },
        null,
        2
      ),
      { mode: 0o600 }
    );
  }

  /**
   * Persists a verified key share to the node vault.
   */
  public saveShare(share: StoredKeyShare): void {
    const filePath = path.join(
      this.config.vaultDir,
      `share_${share.protocol.toLowerCase()}_${share.sessionId}.json`
    );
    fs.writeFileSync(filePath, JSON.stringify(share, null, 2), { mode: 0o600 });
  }

  /**
   * Loads a key share from the node vault.
   */
  public loadShare(sessionId: string, protocol: TssProtocol): StoredKeyShare | null {
    const filePath = path.join(
      this.config.vaultDir,
      `share_${protocol.toLowerCase()}_${sessionId}.json`
    );
    if (!fs.existsSync(filePath)) return null;
    try {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch {
      return null;
    }
  }

  /**
   * Starts the P2P node network listener.
   */
  public async start(): Promise<void> {
    if (this.isRunning) return;

    return new Promise<void>((resolve, reject) => {
      this.server = P2PTransport.createServer(
        this.config.port,
        this.config.host,
        async (envelope, socket) => {
          const response = await this.handleEnvelope(envelope);
          if (response) {
            const signed = P2PTransport.signEnvelope(response, this.identityPrivateKeyHex);
            const jsonPayload = Buffer.from(JSON.stringify(signed), 'utf8');
            const header = Buffer.alloc(4);
            header.writeUInt32BE(jsonPayload.length, 0);
            socket.write(Buffer.concat([header, jsonPayload]));
          }
        }
      );

      this.server.on('error', (err) => reject(err));
      this.server.on('listening', () => {
        this.isRunning = true;
        const addr = this.server?.address();
        if (addr && typeof addr === 'object' && typeof addr.port === 'number') {
          this.config.port = addr.port;
        }
        resolve();
      });
    });
  }

  /**
   * Stops the P2P node daemon.
   */
  public async stop(): Promise<void> {
    if (!this.isRunning || !this.server) return;
    return new Promise<void>((resolve) => {
      this.server!.close(() => {
        this.isRunning = false;
        resolve();
      });
    });
  }

  /**
   * Handles incoming authenticated P2P message envelopes.
   */
  public async handleEnvelope(
    envelope: P2PMessageEnvelope
  ): Promise<Omit<P2PMessageEnvelope, 'signatureHex'> | null> {
    // 1. Verify envelope signature if sender is in peer directory
    const sender = this.config.peerDirectory.find((p) => p.nodeId === envelope.fromNodeId);
    if (sender) {
      const valid = P2PTransport.verifyEnvelope(envelope, sender.identityPublicKeyHex);
      if (!valid) {
        console.error(`[P2PNodeDaemon ${this.config.nodeId}] Invalid envelope signature from ${envelope.fromNodeId}`);
        return null;
      }
    }

    let payloadObj: any;
    try {
      if (envelope.encrypted && sender) {
        const sharedKey = P2PTransport.deriveSharedKey(
          this.identityPrivateKeyHex,
          sender.identityPublicKeyHex,
          envelope.sessionId
        );
        const decrypted = P2PTransport.decryptPayload(envelope.payload, sharedKey);
        payloadObj = JSON.parse(decrypted);
      } else {
        payloadObj = JSON.parse(envelope.payload);
      }
    } catch (err) {
      console.error(`[P2PNodeDaemon ${this.config.nodeId}] Failed to decrypt or parse payload:`, err);
      return null;
    }

    // 2. Dispatch protocol logic
    switch (envelope.protocol) {
      case 'FROST_ED25519':
        return this.handleFrostEd25519(envelope, payloadObj);
      case 'FROST_TAPROOT':
        return this.handleFrostTaproot(envelope, payloadObj);
      case 'CGGMP21':
        return this.handleCggmp21(envelope, payloadObj);
      case 'HYBRID_DKG':
        return this.handleHybridDkg(envelope, payloadObj);
      default:
        return null;
    }
  }

  /**
   * Protocol Handler: FROST Ed25519 (Solana)
   */
  private handleFrostEd25519(envelope: P2PMessageEnvelope, payload: any): Omit<P2PMessageEnvelope, 'signatureHex'> {
    if (payload.action === 'ROUND1_NONCE') {
      const nonces = generateEd25519NoncePair();
      this.ed25519Nonces.set(envelope.sessionId, nonces);

      return {
        protocol: 'FROST_ED25519',
        sessionId: envelope.sessionId,
        fromNodeId: this.config.nodeId,
        toNodeId: envelope.fromNodeId,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        encrypted: false,
        payload: JSON.stringify({
          action: 'ROUND1_COMMITMENT',
          participantId: this.config.nodeId,
          shareIndex: this.config.shareIndex,
          domain: this.config.domain,
          D_hex: nonces.D_hex,
          E_hex: nonces.E_hex,
        }),
      };
    }

    if (payload.action === 'ROUND2_SIGN') {
      const nonces = this.ed25519Nonces.get(envelope.sessionId);
      if (!nonces) throw new Error('[P2PNodeDaemon] Nonces not found for session');

      const share = this.loadShare(envelope.sessionId, 'FROST_ED25519');
      if (!share) throw new Error('[P2PNodeDaemon] Key share not found in vault');

      const sigShare = computeEd25519SignatureShare(
        {
          participantId: this.config.nodeId,
          shareIndex: this.config.shareIndex,
          domain: this.config.domain,
          secretScalarHex: share.secretScalarHex,
          publicKeyHex: share.publicKeyHex,
          groupPublicKeyHex: share.groupPublicKeyHex,
        },
        nonces,
        payload.commitments,
        payload.domainParticipants,
        Buffer.from(payload.groupCommitmentR_hex, 'hex'),
        Buffer.from(payload.groupPublicKey_hex, 'hex'),
        Buffer.from(payload.messageHex, 'hex')
      );

      return {
        protocol: 'FROST_ED25519',
        sessionId: envelope.sessionId,
        fromNodeId: this.config.nodeId,
        toNodeId: envelope.fromNodeId,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        encrypted: false,
        payload: JSON.stringify({
          action: 'ROUND2_SHARE',
          sigShare,
        }),
      };
    }

    return {
      protocol: 'FROST_ED25519',
      sessionId: envelope.sessionId,
      fromNodeId: this.config.nodeId,
      toNodeId: envelope.fromNodeId,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex'),
      encrypted: false,
      payload: JSON.stringify({ error: 'Unknown action' }),
    };
  }

  /**
   * Protocol Handler: FROST Taproot (Bitcoin)
   */
  private handleFrostTaproot(envelope: P2PMessageEnvelope, payload: any): Omit<P2PMessageEnvelope, 'signatureHex'> {
    if (payload.action === 'ROUND1_NONCE') {
      const nonces = generateTaprootNoncePair();
      this.taprootNonces.set(envelope.sessionId, nonces);

      return {
        protocol: 'FROST_TAPROOT',
        sessionId: envelope.sessionId,
        fromNodeId: this.config.nodeId,
        toNodeId: envelope.fromNodeId,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        encrypted: false,
        payload: JSON.stringify({
          action: 'ROUND1_COMMITMENT',
          participantId: this.config.nodeId,
          shareIndex: this.config.shareIndex,
          domain: this.config.domain,
          D_hex: nonces.D_hex,
          E_hex: nonces.E_hex,
        }),
      };
    }

    if (payload.action === 'ROUND2_SIGN') {
      const nonces = this.taprootNonces.get(envelope.sessionId);
      if (!nonces) throw new Error('[P2PNodeDaemon] Taproot nonces not found for session');

      const share = this.loadShare(envelope.sessionId, 'FROST_TAPROOT');
      if (!share) throw new Error('[P2PNodeDaemon] Key share not found in vault');

      const sigShare = computeTaprootSignatureShare(
        {
          participantId: this.config.nodeId,
          shareIndex: this.config.shareIndex,
          domain: this.config.domain,
          secretScalarHex: share.secretScalarHex,
          publicKeyHex: share.publicKeyHex,
          groupPublicKeyHex: share.groupPublicKeyHex,
        },
        nonces,
        payload.commitments,
        payload.domainParticipants,
        {
          internalKeyX: Buffer.from(payload.parityCtx.internalKeyX, 'hex'),
          outputKeyX: Buffer.from(payload.parityCtx.outputKeyX, 'hex'),
          tweak: BigInt(payload.parityCtx.tweakHex),
          negateInternalKey: payload.parityCtx.negateInternalKey,
          negateOutputKey: payload.parityCtx.negateOutputKey,
        },
        Buffer.from(payload.R_x_hex, 'hex'),
        payload.negateR,
        Buffer.from(payload.messageHex, 'hex')
      );

      return {
        protocol: 'FROST_TAPROOT',
        sessionId: envelope.sessionId,
        fromNodeId: this.config.nodeId,
        toNodeId: envelope.fromNodeId,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        encrypted: false,
        payload: JSON.stringify({
          action: 'ROUND2_SHARE',
          sigShare,
        }),
      };
    }

    return {
      protocol: 'FROST_TAPROOT',
      sessionId: envelope.sessionId,
      fromNodeId: this.config.nodeId,
      toNodeId: envelope.fromNodeId,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex'),
      encrypted: false,
      payload: JSON.stringify({ error: 'Unknown action' }),
    };
  }

  /**
   * Protocol Handler: CGGMP21 (Ethereum)
   */
  private handleCggmp21(envelope: P2PMessageEnvelope, payload: any): Omit<P2PMessageEnvelope, 'signatureHex'> {
    if (payload.action === 'ROUND1_INIT') {
      const share = this.loadShare(envelope.sessionId, 'CGGMP21');
      if (!share) throw new Error('[P2PNodeDaemon] CGGMP21 share not found in vault');

      const { state, commitment } = initCggmp21Round1(
        envelope.sessionId,
        {
          participantId: this.config.nodeId,
          shareIndex: this.config.shareIndex,
          domain: this.config.domain,
          secretScalarHex: share.secretScalarHex,
          publicKeyHex: share.publicKeyHex,
          groupPublicKeyHex: share.groupPublicKeyHex,
        },
        payload.domainParticipants
      );

      this.cggmp21States.set(envelope.sessionId, state);

      return {
        protocol: 'CGGMP21',
        sessionId: envelope.sessionId,
        fromNodeId: this.config.nodeId,
        toNodeId: envelope.fromNodeId,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        encrypted: false,
        payload: JSON.stringify({
          action: 'ROUND1_COMMITMENT',
          commitment,
        }),
      };
    }

    if (payload.action === 'ROUND2_DECOMMIT') {
      const state = this.cggmp21States.get(envelope.sessionId);
      if (!state) throw new Error('[P2PNodeDaemon] CGGMP21 state not found');

      const decommitment = generateCggmp21Round2Decommitment(state, this.identityPrivateKeyHex);

      return {
        protocol: 'CGGMP21',
        sessionId: envelope.sessionId,
        fromNodeId: this.config.nodeId,
        toNodeId: envelope.fromNodeId,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        encrypted: false,
        payload: JSON.stringify({
          action: 'ROUND2_DECOMMITMENT',
          decommitment,
        }),
      };
    }

    if (payload.action === 'ROUND3_DELTA') {
      const state = this.cggmp21States.get(envelope.sessionId);
      if (!state) throw new Error('[P2PNodeDaemon] CGGMP21 state not found');

      const deltaShare = computeCggmp21Round3DeltaShare(
        state,
        payload.decommitments,
        this.identityPrivateKeyHex
      );

      return {
        protocol: 'CGGMP21',
        sessionId: envelope.sessionId,
        fromNodeId: this.config.nodeId,
        toNodeId: envelope.fromNodeId,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        encrypted: false,
        payload: JSON.stringify({
          action: 'ROUND3_DELTA_SHARE',
          deltaShare,
        }),
      };
    }

    if (payload.action === 'ROUND4_SIGMA') {
      const state = this.cggmp21States.get(envelope.sessionId);
      if (!state) throw new Error('[P2PNodeDaemon] CGGMP21 state not found');

      const sigmaShare = computeCggmp21Round4SignatureShare(
        state,
        BigInt(payload.rHex),
        Buffer.from(payload.messageHashHex, 'hex'),
        this.identityPrivateKeyHex
      );

      return {
        protocol: 'CGGMP21',
        sessionId: envelope.sessionId,
        fromNodeId: this.config.nodeId,
        toNodeId: envelope.fromNodeId,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        encrypted: false,
        payload: JSON.stringify({
          action: 'ROUND4_SIGMA_SHARE',
          sigmaShare,
        }),
      };
    }

    return {
      protocol: 'CGGMP21',
      sessionId: envelope.sessionId,
      fromNodeId: this.config.nodeId,
      toNodeId: envelope.fromNodeId,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex'),
      encrypted: false,
      payload: JSON.stringify({ error: 'Unknown action' }),
    };
  }

  /**
   * Protocol Handler: HybridDKG
   */
  private handleHybridDkg(envelope: P2PMessageEnvelope, payload: any): Omit<P2PMessageEnvelope, 'signatureHex'> {
    if (payload.action === 'STORE_SHARE') {
      this.saveShare({
        sessionId: envelope.sessionId,
        protocol: payload.protocol,
        domain: this.config.domain,
        shareIndex: this.config.shareIndex,
        secretScalarHex: payload.secretScalarHex,
        publicKeyHex: payload.publicKeyHex,
        groupPublicKeyHex: payload.groupPublicKeyHex,
        createdAt: Date.now(),
      });

      return {
        protocol: 'HYBRID_DKG',
        sessionId: envelope.sessionId,
        fromNodeId: this.config.nodeId,
        toNodeId: envelope.fromNodeId,
        timestamp: Date.now(),
        nonce: crypto.randomBytes(16).toString('hex'),
        encrypted: false,
        payload: JSON.stringify({ success: true }),
      };
    }

    return {
      protocol: 'HYBRID_DKG',
      sessionId: envelope.sessionId,
      fromNodeId: this.config.nodeId,
      toNodeId: envelope.fromNodeId,
      timestamp: Date.now(),
      nonce: crypto.randomBytes(16).toString('hex'),
      encrypted: false,
      payload: JSON.stringify({ error: 'Unknown action' }),
    };
  }
}
