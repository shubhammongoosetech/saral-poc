/**
 * mpcCoordinator.ts
 *
 * Stateless MPC Session Coordinator for SARAL Decentralized Threshold ECDSA.
 *
 * Security Invariants:
 *   - The coordinator strictly interacts with independent participants via IMpcParticipantClient.
 *   - Zero In-Process Daemon Fallback: In-process direct execution is strictly prohibited in the coordinator.
 *   - The coordinator NEVER holds, requests, or receives private Shamir shares or nonce shares.
 *   - Functions as an untrusted session router, commitment broadcaster, and signature aggregator.
 *   - A complete memory dump or compromise of the coordinator process reveals ZERO secret keys.
 *   - Enforces strict 3-Domain Separation of Powers quorums before session dispatch.
 */

import crypto from 'crypto';
import { ethers } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  modInverse,
  scalarToHex,
  G,
} from './secp256k1Math';
import {
  MpcSessionConfig,
  DistributedMpcSigningResult,
  Round1CommitmentMessage,
  Round1DecommitmentMessage,
  Round2PairwiseMtaPacket,
  Round2DeltaShareMessage,
  Round3PartialSignatureMessage,
} from './mpcProtocolTypes';
import {
  IMpcParticipantClient,
  verifyParticipantSignature,
} from '../participant/participantTransport';
import { trustedParticipantRegistry } from './participantRegistry';

export class StatelessMpcCoordinator {
  /**
   * Orchestrates the 3-Domain Interactive Threshold ECDSA Signing Protocol
   * strictly across independent participant clients (IMpcParticipantClient[]).
   */
  public async coordinateSigningSession(
    participants: IMpcParticipantClient[],
    unsignedTxSerialized: string,
    chainId: bigint,
    expectedAggregatedPublicKeyHex: string,
    commitments?: {
      foundation: string[];
      public: string[];
      private: string[];
    },
    minPublicThreshold: number = 5,
    minPrivateThreshold: number = 5,
    minFoundationThreshold: number = 1
  ): Promise<DistributedMpcSigningResult> {
    const totalStart = Date.now();

    // Boundary and parameter validation
    if (!Array.isArray(participants) || participants.length === 0) {
      throw new Error('[Coordinator Security Gate] Invalid participants list: non-empty array required');
    }

    // Verify participant identities against authoritative enrollment registry
    for (const p of participants) {
      const endpoint = p.endpoint;
      const enrolledCheck = trustedParticipantRegistry.verifyEnrolledIdentity(
        p.id,
        p.identityPublicKeyHex,
        p.domain,
        endpoint
      );
      if (!enrolledCheck.valid) {
        throw new Error(
          `[Coordinator Security Gate] Participant '${p.id}' failed enrollment check: ${enrolledCheck.reason}`
        );
      }
    }

    // Verify separation of powers and minimum threshold quorums
    const foundationDaemons = participants.filter((d) => d.domain === 'FOUNDATION');
    const publicDaemons = participants.filter((d) => d.domain === 'PUBLIC');
    const privateDaemons = participants.filter((d) => d.domain === 'PRIVATE');

    if (foundationDaemons.length < minFoundationThreshold) {
      throw new Error(
        `[MPC Authorization Failure] Foundation domain threshold not met: require >= ${minFoundationThreshold} nodes, got ${foundationDaemons.length}`
      );
    }
    if (publicDaemons.length < minPublicThreshold) {
      throw new Error(
        `[MPC Authorization Failure] Public domain threshold not met: require >= ${minPublicThreshold} nodes, got ${publicDaemons.length}`
      );
    }
    if (privateDaemons.length < minPrivateThreshold) {
      throw new Error(
        `[MPC Authorization Failure] Private domain threshold not met: require >= ${minPrivateThreshold} nodes, got ${privateDaemons.length}`
      );
    }

    // Configure ephemeral signing session
    const sessionId = `saral-mpc-${Date.now()}-${ethers.hexlify(ethers.randomBytes(8)).slice(2)}`;
    const msgHashHex = ethers.keccak256(unsignedTxSerialized);
    const messageScalar = modN(BigInt(msgHashHex));

    const sessionConfig: MpcSessionConfig = {
      sessionId,
      unsignedTxSerialized,
      chainId,
      msgHashHex,
      messageScalar,
      participants: participants.map((d) => ({
        id: d.id,
        domain: d.domain,
        shareIndex: d.shareIndex,
        nodeIndex: d.nodeIndex,
        publicKeyHex: d.identityPublicKeyHex,
        identityPublicKeyHex: d.identityPublicKeyHex,
      })),
      thresholds: {
        foundation: minFoundationThreshold,
        public: minPublicThreshold,
        private: minPrivateThreshold,
      },
      expectedAggregatedPublicKeyHex,
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000, // 60s expiration window
    };

    try {
      // Round 1: Nonce commitment exchange and decommitment broadcast
      const r1Start = Date.now();

      // 1A. Dispatch session init to all participants in parallel
      const commitmentsPromises = participants.map((participant) => {
        let nodeCommitments: string[] | undefined;
        if (commitments) {
          if (participant.domain === 'FOUNDATION') nodeCommitments = commitments.foundation;
          else if (participant.domain === 'PUBLIC') nodeCommitments = commitments.public;
          else if (participant.domain === 'PRIVATE') nodeCommitments = commitments.private;
        }
        return participant.initSession(sessionConfig, nodeCommitments);
      });

      const round1Commitments: Round1CommitmentMessage[] = await Promise.all(commitmentsPromises);

      // 1B. Verify asymmetric digital signatures on all Round 1 commitments
      for (const commit of round1Commitments) {
        const daemon = participants.find((d) => d.id === commit.from);
        if (!daemon) {
          throw new Error(`[Coordinator] Unknown daemon '${commit.from}' in commitments`);
        }
        const expectedMsg = `ROUND1_COMMIT:${sessionId}:${commit.commitmentHex}`;
        if (!verifyParticipantSignature(expectedMsg, commit.signatureHex, daemon.identityPublicKeyHex)) {
          throw new Error(`[Coordinator] Invalid digital signature on commitment from '${commit.from}'`);
        }
      }

      // 1C. Dispatch decommit requests to all participants in parallel
      const decommitPromises = participants.map((participant) => participant.decommit(sessionId));
      const round1Decommitments: Round1DecommitmentMessage[] = await Promise.all(decommitPromises);

      // 1D. Verify decommitment signatures and match against commitments
      let Gamma: typeof G | null = null;
      for (const decommit of round1Decommitments) {
        const daemon = participants.find((d) => d.id === decommit.from);
        if (!daemon) {
          throw new Error(`[Coordinator] Unknown daemon '${decommit.from}' in decommitments`);
        }

        // Verify asymmetric signature of decommitment
        const expectedDecommitMsg = `ROUND1_DECOMMIT:${sessionId}:${decommit.gammaPointHex}:${decommit.paillierNHex}:${decommit.encryptedGammaHex}:${decommit.encryptedWHex}`;
        if (!verifyParticipantSignature(expectedDecommitMsg, decommit.signatureHex, daemon.identityPublicKeyHex)) {
          throw new Error(`[Coordinator] Invalid digital signature on decommitment from '${decommit.from}'`);
        }

        const commit = round1Commitments.find((c) => c.from === decommit.from);
        if (!commit) {
          throw new Error(`[Coordinator] Missing commitment for participant ${decommit.from}`);
        }

        // Check SHA256(sessionId || from || Gamma_i || paillierN || encGamma || encW) == C_i
        const cleanHex = decommit.gammaPointHex.startsWith('0x')
          ? decommit.gammaPointHex.slice(2)
          : decommit.gammaPointHex;
        const expectedCommit = crypto
          .createHash('sha256')
          .update(
            `${sessionId}:${decommit.from}:${cleanHex}:${decommit.paillierNHex}:${decommit.encryptedGammaHex}:${decommit.encryptedWHex}`
          )
          .digest('hex');

        if (expectedCommit !== commit.commitmentHex) {
          throw new Error(`[Coordinator] Commitment mismatch detected from participant ${decommit.from}`);
        }

        const point = secp256k1.ProjectivePoint.fromHex(cleanHex);
        Gamma = Gamma ? Gamma.add(point) : point;
      }

      if (!Gamma) throw new Error('[Coordinator] Failed to aggregate Gamma curve point');
      const r1Duration = Date.now() - r1Start;

      // Round 2: Pairwise MtA protocol relay and delta aggregation
      const r2Start = Date.now();

      // 2A. Instruct all participants to generate encrypted pairwise MtA packets
      const packetGenerations = await Promise.all(
        participants.map((d) => d.generateMtaPackets(sessionId, round1Decommitments))
      );

      // 2B. Aggregate and group packets by destination daemon
      const allPackets: Round2PairwiseMtaPacket[] = [];
      for (const gen of packetGenerations) {
        allPackets.push(...gen.packets);
      }

      const packetsByRecipient = new Map<string, Round2PairwiseMtaPacket[]>();
      for (const packet of allPackets) {
        const existing = packetsByRecipient.get(packet.to) || [];
        existing.push(packet);
        packetsByRecipient.set(packet.to, existing);
      }

      // 2C. Route pairwise packets to recipients & collect local delta shares
      const deltaPromises = participants.map((participant) => {
        const incoming = packetsByRecipient.get(participant.id) || [];
        return participant.processMtaPackets(sessionId, incoming);
      });

      const deltaMessages: Round2DeltaShareMessage[] = await Promise.all(deltaPromises);

      // 2D. Verify digital signatures on delta shares & aggregate delta = sum(delta_i) mod n
      let delta = 0n;
      for (const msg of deltaMessages) {
        const daemon = participants.find((d) => d.id === msg.from);
        if (!daemon) {
          throw new Error(`[Coordinator] Unknown daemon '${msg.from}' in delta shares`);
        }
        const expectedDeltaMsg = `ROUND2_DELTA:${sessionId}:${msg.deltaShareHex}`;
        if (!verifyParticipantSignature(expectedDeltaMsg, msg.signatureHex, daemon.identityPublicKeyHex)) {
          throw new Error(`[Coordinator] Invalid digital signature on delta share from '${msg.from}'`);
        }

        const d_i = BigInt('0x' + msg.deltaShareHex);
        delta = modN(delta + d_i);
      }

      if (delta === 0n) {
        throw new Error('[Coordinator] Nonce delta is degenerate (0 mod n). Aborting session.');
      }

      const deltaInv = modInverse(delta, CURVE_ORDER);

      /**
       * Mathematical Derivation (Gennaro-Goldfeder GG18/GG20 Inverted Nonce Convention):
       *   delta = k * gamma mod n
       *   Gamma = gamma * G
       *   R = delta^-1 * Gamma = (k * gamma)^-1 * (gamma * G) = k^-1 * G
       * Effective discrete log of R is k_eff = k^-1 mod n.
       * Standard ECDSA requires: s = (k_eff)^-1 * (m + r*x) = k * (m + r*x) mod n.
       */
      const R = Gamma.multiply(deltaInv);
      const r = modN(R.x);

      if (r === 0n) {
        throw new Error('[Coordinator] Nonce point collision: r = 0 mod n. Aborting session.');
      }

      let yParity: 0 | 1 = R.y % 2n === 1n ? 1 : 0;
      const r2Duration = Date.now() - r2Start;

      // Round 3: Partial signature collection and signature aggregation
      const r3Start = Date.now();

      // 3A. Broadcast curve point r to all participants and collect partial signatures
      const partialSigPromises = participants.map((d) => d.computePartialSignature(sessionId, r));
      const round3PartialSigs: Round3PartialSignatureMessage[] = await Promise.all(partialSigPromises);

      // 3B. Verify signatures on partial contributions & aggregate: s = sum(s_i) mod n
      let aggregatedS = 0n;
      for (const pSig of round3PartialSigs) {
        const daemon = participants.find((d) => d.id === pSig.from);
        if (!daemon) {
          throw new Error(`[Coordinator] Unknown daemon '${pSig.from}' in partial signatures`);
        }
        const expectedSigMsg = `ROUND3_PARTIAL_SIG:${sessionId}:${pSig.sShareHex}`;
        if (!verifyParticipantSignature(expectedSigMsg, pSig.signatureHex, daemon.identityPublicKeyHex)) {
          throw new Error(`[Coordinator] Invalid digital signature on partial signature from '${pSig.from}'`);
        }

        const s_i = BigInt('0x' + pSig.sShareHex);
        aggregatedS = modN(aggregatedS + s_i);
      }

      if (aggregatedS === 0n) {
        throw new Error('[Coordinator] Signature scalar s = 0 mod n. Aborting session.');
      }

      // 3C. Enforce canonical low-s (BIP-62 / EIP-2)
      const halfOrder = CURVE_ORDER / 2n;
      let finalS = aggregatedS;
      if (finalS > halfOrder) {
        finalS = modN(CURVE_ORDER - finalS);
        yParity = yParity === 1 ? 0 : 1;
      }

      const r3Duration = Date.now() - r3Start;
      const totalDuration = Date.now() - totalStart;

      // Verification against aggregated public key
      const rHex = '0x' + scalarToHex(r);
      const sHex = '0x' + scalarToHex(finalS);

      const sig = ethers.Signature.from({
        r: rHex,
        s: sHex,
        yParity,
      });

      const recoveredAddress = ethers.recoverAddress(msgHashHex, sig);
      if (expectedAggregatedPublicKeyHex) {
        const cleanExpectedPk = expectedAggregatedPublicKeyHex.startsWith('0x')
          ? expectedAggregatedPublicKeyHex
          : '0x' + expectedAggregatedPublicKeyHex;
        const expectedAddress = ethers.computeAddress(cleanExpectedPk);

        if (recoveredAddress.toLowerCase() !== expectedAddress.toLowerCase()) {
          throw new Error(
            `[Coordinator] Cryptographic signature verification failed: recovered ${recoveredAddress}, expected ${expectedAddress}`
          );
        }
      }

      // Raw signed transaction serialization (supports EVM and non-EVM / Solana)
      let rawSignedTx: string;
      let txHash: string;
      let v: number;

      try {
        const unsignedTxObj = ethers.Transaction.from(unsignedTxSerialized);
        v = Number(chainId * 2n + 35n + BigInt(yParity));

        const signedTx = ethers.Transaction.from({
          to: unsignedTxObj.to,
          nonce: unsignedTxObj.nonce,
          gasLimit: unsignedTxObj.gasLimit,
          gasPrice: unsignedTxObj.gasPrice,
          maxFeePerGas: unsignedTxObj.maxFeePerGas,
          maxPriorityFeePerGas: unsignedTxObj.maxPriorityFeePerGas,
          data: unsignedTxObj.data,
          value: unsignedTxObj.value,
          chainId,
          type: unsignedTxObj.type,
          signature: sig,
        });

        rawSignedTx = signedTx.serialized;
        txHash = signedTx.hash || ethers.keccak256(rawSignedTx);
      } catch {
        // Non-EVM payload (e.g. Solana Devnet transaction payload)
        v = yParity === 1 ? 28 : 27;
        rawSignedTx = ethers.hexlify(
          ethers.toUtf8Bytes(
            JSON.stringify({
              payload: unsignedTxSerialized,
              signature: { r: rHex, s: sHex, yParity, v },
            })
          )
        );
        txHash = ethers.keccak256(rawSignedTx);
      }

      return {
        sessionId,
        r: rHex,
        s: sHex,
        yParity,
        v,
        rawSignedTx,
        txHash,
        signingQuorum: {
          foundationAuthorized: foundationDaemons.length >= 1,
          publicNodeCount: publicDaemons.length,
          privateNodeCount: privateDaemons.length,
        },
        participatingNodes: {
          foundation: foundationDaemons.map((d) => d.id),
          publicDomain: publicDaemons.map((d) => d.id),
          privateDomain: privateDaemons.map((d) => d.id),
        },
        metrics: {
          round1DurationMs: r1Duration,
          round2DurationMs: r2Duration,
          round3DurationMs: r3Duration,
          totalDurationMs: totalDuration,
        },
      };
    } catch (err: any) {
      // Broadcast session abort to all participants
      await Promise.all(
        participants.map(async (d) => {
          try {
            if (typeof d.abortSession === 'function') {
              await d.abortSession(sessionId, err.message);
            }
          } catch {}
        })
      );
      throw err;
    }
  }
}

// Global coordinator singleton
export const statelessMpcCoordinator = new StatelessMpcCoordinator();
