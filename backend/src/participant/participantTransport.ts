/**
 * participantTransport.ts
 *
 * Network & RPC Transport Interfaces for Independent MPC Participants
 *
 * Core Security Rule:
 *   The coordinator interacts ONLY with this transport client interface.
 *   The coordinator NEVER receives, holds, or accesses:
 *     - Participant private Shamir shares (s_i)
 *     - Effective additive shares (w_i)
 *     - Paillier private keys
 *     - Ephemeral nonce shares (k_i, gamma_i)
 *     - Participant internal session heap memory
 */

import crypto from 'crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
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

/**
 * Interface that the Coordinator uses to communicate with an independent participant service.
 */
export interface IMpcParticipantClient {
  readonly id: ParticipantId;
  readonly domain: DomainType;
  readonly nodeIndex: number;
  readonly shareIndex: number;
  readonly identityPublicKeyHex: string;
  readonly endpoint: string;

  /**
   * Round 1: Session Initiation & Nonce Commitment
   */
  initSession(
    config: MpcSessionConfig,
    commitmentsHex?: string[]
  ): Promise<Round1CommitmentMessage>;

  /**
   * Round 1: Decommitment Request
   */
  decommit(sessionId: string): Promise<Round1DecommitmentMessage>;

  /**
   * Round 2: Pairwise MtA Packet Generation
   */
  generateMtaPackets(
    sessionId: string,
    allDecommitments: Round1DecommitmentMessage[]
  ): Promise<{ packets: Round2PairwiseMtaPacket[] }>;

  /**
   * Round 2: Process Incoming Pairwise MtA Packets & Compute Delta Share
   */
  processMtaPackets(
    sessionId: string,
    incomingPackets: Round2PairwiseMtaPacket[]
  ): Promise<Round2DeltaShareMessage>;

  /**
   * Round 3: Compute Partial Signature & Wipe Ephemeral Nonces
   */
  computePartialSignature(
    sessionId: string,
    r: bigint
  ): Promise<Round3PartialSignatureMessage>;

  /**
   * Aborts session and zeroizes ephemeral memory.
   */
  abortSession(sessionId: string, reason: string): Promise<void>;
}

/**
 * Verifies secp256k1 digital signatures on MPC protocol messages.
 */
export function verifyParticipantSignature(
  message: string,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  try {
    const hash = crypto.createHash('sha256').update(message).digest();
    const cleanPub = publicKeyHex.startsWith('0x') ? publicKeyHex.slice(2) : publicKeyHex;
    return secp256k1.verify(signatureHex, hash, cleanPub);
  } catch {
    return false;
  }
}
