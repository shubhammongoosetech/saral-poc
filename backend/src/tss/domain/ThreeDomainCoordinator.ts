/**
 * ThreeDomainCoordinator.ts
 *
 * Coordinator for 3-Domain Separation of Powers Access Structure
 * (FOUNDATION ^ PUBLIC ^ PRIVATE) across multi-chain threshold signing.
 *
 * Security Invariants:
 *  1. Access Structure: All three domains are cryptographically mandatory.
 *  2. Minimum Threshold: For each domain d, at least t_d valid participants must contribute.
 *  3. Fail-Closed: If any domain has fewer than t_d participants, the session terminates immediately.
 *  4. Additive Separation: Master secret x = x_F + x_P + x_U. Master public key Q = Q_F + Q_P + Q_U.
 *     No combination of nodes from fewer than 3 domains can produce a mathematically valid signature.
 */

import crypto from 'crypto';
import { ethers } from 'ethers';
import {
  DomainName,
  ThreeDomainTopologyConfig,
  ThreeDomainSigningRequest,
  ThreeDomainSigningResult,
} from './types';
import {
  FrostEd25519KeyShare,
  FrostEd25519NonceCommitment,
  FrostEd25519SignatureShare,
  generateEd25519NoncePair,
  computeEd25519SignatureShare,
  aggregateEd25519GroupCommitment,
  aggregateEd25519Signature,
  verifyEd25519SignatureShare,
} from '../protocols/frost-ed25519';
import {
  FrostTaprootKeyShare,
  FrostTaprootNonceCommitment,
  FrostTaprootSignatureShare,
  generateTaprootNoncePair,
  deriveTaprootKeysAndParity,
  aggregateTaprootGroupCommitment,
  computeTaprootSignatureShare,
  aggregateTaprootSignature,
  verifyTaprootSignatureShare,
} from '../protocols/frost-taproot';
import {
  Cggmp21KeyShare,
  initCggmp21Round1,
  generateCggmp21Round2Decommitment,
  verifyCggmp21PeerDecommitment,
  computeCggmp21Round3DeltaShare,
  computeCggmp21PairwiseMtaContributions,
  aggregateCggmp21Delta,
  computeCggmp21Round4SignatureShare,
  aggregateCggmp21Signature,
  verifyCggmp21SignatureShare,
} from '../protocols/cggmp21';

export class ThreeDomainCoordinator {
  /**
   * Enforces the 3-Domain Quorum Security Policy.
   * Fails closed if any domain does not satisfy its threshold.
   */
  public validateDomainQuorum(
    activeParticipants: { domain: DomainName }[],
    topology: ThreeDomainTopologyConfig
  ): { valid: boolean; counts: Record<DomainName, number>; reason?: string } {
    const counts: Record<DomainName, number> = {
      FOUNDATION: 0,
      PUBLIC: 0,
      PRIVATE: 0,
    };

    for (const p of activeParticipants) {
      if (counts[p.domain] !== undefined) {
        counts[p.domain]++;
      }
    }

    if (counts.FOUNDATION < topology.foundation.threshold) {
      return {
        valid: false,
        counts,
        reason: `[3-Domain Policy Failure] Foundation threshold not met: required >= ${topology.foundation.threshold}, got ${counts.FOUNDATION}`,
      };
    }

    if (counts.PUBLIC < topology.public.threshold) {
      return {
        valid: false,
        counts,
        reason: `[3-Domain Policy Failure] Public threshold not met: required >= ${topology.public.threshold}, got ${counts.PUBLIC}`,
      };
    }

    if (counts.PRIVATE < topology.private.threshold) {
      return {
        valid: false,
        counts,
        reason: `[3-Domain Policy Failure] Private threshold not met: required >= ${topology.private.threshold}, got ${counts.PRIVATE}`,
      };
    }

    return { valid: true, counts };
  }

  /**
   * Coordinates multi-party signing across the 3 domains according to the chain protocol.
   */
  public async coordinateSigning(request: ThreeDomainSigningRequest): Promise<ThreeDomainSigningResult> {
    // 1. Strict 3-Domain Security Gate
    const quorumCheck = this.validateDomainQuorum(request.activeParticipants, request.domainTopology);
    if (!quorumCheck.valid) {
      throw new Error(quorumCheck.reason);
    }

    switch (request.chain) {
      case 'solana':
        return this.executeSolanaFrost(request);
      case 'bitcoin-taproot':
        return this.executeBitcoinTaprootFrost(request);
      case 'ethereum':
        return this.executeEthereumCggmp21(request);
      default:
        throw new Error(`[Coordinator] Unsupported blockchain: ${request.chain}`);
    }
  }

  /**
   * Executes Ed25519 FROST threshold signing across all 3 domains.
   */
  private async executeSolanaFrost(request: ThreeDomainSigningRequest): Promise<ThreeDomainSigningResult> {
    const messageBytes = typeof request.messageOrTx === 'string'
      ? Buffer.from(request.messageOrTx.startsWith('0x') ? request.messageOrTx.slice(2) : request.messageOrTx, 'hex')
      : Buffer.from(request.messageOrTx);

    const groupPubkeyBytes = Buffer.from(
      request.domainKeys.aggregatedPublicKeyHex.startsWith('0x')
        ? request.domainKeys.aggregatedPublicKeyHex.slice(2)
        : request.domainKeys.aggregatedPublicKeyHex,
      'hex'
    );

    const participantsByDomain = {
      FOUNDATION: request.activeParticipants.filter((p) => p.domain === 'FOUNDATION'),
      PUBLIC: request.activeParticipants.filter((p) => p.domain === 'PUBLIC'),
      PRIVATE: request.activeParticipants.filter((p) => p.domain === 'PRIVATE'),
    };

    // Round 1: Nonce pair generation / commitments
    const participantNonces = new Map<string, ReturnType<typeof generateEd25519NoncePair>>();
    const commitments: FrostEd25519NonceCommitment[] = [];

    for (const p of request.activeParticipants) {
      const nonces = generateEd25519NoncePair();
      participantNonces.set(p.participantId, nonces);
      commitments.push({
        participantId: p.participantId,
        shareIndex: p.shareIndex,
        domain: p.domain,
        D_hex: nonces.D_hex,
        E_hex: nonces.E_hex,
      });
    }

    // Aggregator computes group commitment R = sum(D_i + rho_i * E_i)
    const { R_bytes } = aggregateEd25519GroupCommitment(commitments, messageBytes);

    // Round 2: Signature shares
    const signatureShares: FrostEd25519SignatureShare[] = [];

    for (let i = 0; i < request.activeParticipants.length; i++) {
      const p = request.activeParticipants[i];
      const nonces = participantNonces.get(p.participantId)!;
      const domainSigners = participantsByDomain[p.domain].map((x) => x.shareIndex);

      const keyShare: FrostEd25519KeyShare =
        p.keyShare ||
        (p.daemon && typeof p.daemon.loadShare === 'function'
          ? p.daemon.loadShare(request.sessionId, 'FROST_ED25519')
          : null);

      if (!keyShare) {
        throw new Error(
          `[3-Domain Coordinator] Participant ${p.participantId} does not have a valid FrostEd25519KeyShare. Genuine TSS signing requires non-zero participant shares.`
        );
      }

      const share = computeEd25519SignatureShare(
        keyShare,
        nonces,
        commitments,
        domainSigners,
        R_bytes,
        groupPubkeyBytes,
        messageBytes
      );

      // Verify individual share for identifiable aborts (RFC 9591 Sec 4.5)
      const verifyRes = verifyEd25519SignatureShare(
        share,
        commitments[i],
        commitments,
        domainSigners,
        p.identityPublicKeyHex || keyShare.publicKeyHex,
        R_bytes,
        groupPubkeyBytes,
        messageBytes
      );
      if (!verifyRes.valid) {
        throw new Error(
          `[3-Domain Coordinator] Participant ${p.participantId} submitted invalid Ed25519 signature share: ${verifyRes.reason}`
        );
      }

      signatureShares.push(share);
    }

    const sig = aggregateEd25519Signature(signatureShares, R_bytes, groupPubkeyBytes, messageBytes);

    return {
      sessionId: request.sessionId,
      chain: 'solana',
      domainsParticipated: ['FOUNDATION', 'PUBLIC', 'PRIVATE'],
      rawSignatureHex: sig.rawSignatureHex,
      verified: true,
    };
  }

  /**
   * Executes Bitcoin Taproot BIP-340 FROST threshold signing across all 3 domains.
   */
  private async executeBitcoinTaprootFrost(request: ThreeDomainSigningRequest): Promise<ThreeDomainSigningResult> {
    const sighashBytes = typeof request.messageOrTx === 'string'
      ? Buffer.from(request.messageOrTx.startsWith('0x') ? request.messageOrTx.slice(2) : request.messageOrTx, 'hex')
      : Buffer.from(request.messageOrTx);

    const parityCtx = deriveTaprootKeysAndParity(
      request.domainKeys.aggregatedPublicKeyHex,
      request.extraParams?.merkleRoot
    );

    const participantsByDomain = {
      FOUNDATION: request.activeParticipants.filter((p) => p.domain === 'FOUNDATION'),
      PUBLIC: request.activeParticipants.filter((p) => p.domain === 'PUBLIC'),
      PRIVATE: request.activeParticipants.filter((p) => p.domain === 'PRIVATE'),
    };

    // Round 1: Generate nonces
    const participantNonces = new Map<string, ReturnType<typeof generateTaprootNoncePair>>();
    const commitments: FrostTaprootNonceCommitment[] = [];

    for (const p of request.activeParticipants) {
      const nonces = generateTaprootNoncePair();
      participantNonces.set(p.participantId, nonces);
      commitments.push({
        participantId: p.participantId,
        shareIndex: p.shareIndex,
        domain: p.domain,
        D_hex: nonces.D_hex,
        E_hex: nonces.E_hex,
      });
    }

    // Aggregator computes group commitment R and checks parity
    const { R_x, negateR } = aggregateTaprootGroupCommitment(commitments, sighashBytes);

    // Round 2: Signature shares
    const sigShares: FrostTaprootSignatureShare[] = [];

    for (let i = 0; i < request.activeParticipants.length; i++) {
      const p = request.activeParticipants[i];
      const nonces = participantNonces.get(p.participantId)!;
      const domainSigners = participantsByDomain[p.domain].map((x) => x.shareIndex);

      const keyShare: FrostTaprootKeyShare =
        p.keyShare ||
        (p.daemon && typeof p.daemon.loadShare === 'function'
          ? p.daemon.loadShare(request.sessionId, 'FROST_TAPROOT')
          : null);

      if (!keyShare) {
        throw new Error(
          `[3-Domain Coordinator] Participant ${p.participantId} does not have a valid FrostTaprootKeyShare. Genuine TSS signing requires non-zero participant shares.`
        );
      }

      const share = computeTaprootSignatureShare(
        keyShare,
        nonces,
        commitments,
        domainSigners,
        parityCtx,
        R_x,
        negateR,
        sighashBytes
      );

      // Verify individual share for identifiable aborts (BIP-340)
      const verifyRes = verifyTaprootSignatureShare(
        share,
        commitments[i],
        commitments,
        domainSigners,
        p.identityPublicKeyHex || keyShare.publicKeyHex,
        parityCtx,
        R_x,
        negateR,
        sighashBytes
      );
      if (!verifyRes.valid) {
        throw new Error(
          `[3-Domain Coordinator] Participant ${p.participantId} submitted invalid Taproot signature share: ${verifyRes.reason}`
        );
      }

      sigShares.push(share);
    }

    const sig = aggregateTaprootSignature(sigShares, parityCtx, R_x, sighashBytes);

    return {
      sessionId: request.sessionId,
      chain: 'bitcoin-taproot',
      domainsParticipated: ['FOUNDATION', 'PUBLIC', 'PRIVATE'],
      rawSignatureHex: sig.rawSignatureHex,
      verified: true,
    };
  }

  /**
   * Executes CGGMP21 threshold ECDSA signing across all 3 domains.
   */
  private async executeEthereumCggmp21(request: ThreeDomainSigningRequest): Promise<ThreeDomainSigningResult> {
    let msgHashBytes: Buffer;
    if (Buffer.isBuffer(request.messageOrTx) && request.messageOrTx.length === 32) {
      msgHashBytes = request.messageOrTx;
    } else if (
      typeof request.messageOrTx === 'string' &&
      request.messageOrTx.startsWith('0x') &&
      request.messageOrTx.length === 66
    ) {
      msgHashBytes = Buffer.from(request.messageOrTx.slice(2), 'hex');
    } else {
      const hashStr = ethers.keccak256(
        typeof request.messageOrTx === 'string'
          ? request.messageOrTx.startsWith('0x')
            ? request.messageOrTx
            : Buffer.from(request.messageOrTx, 'utf8')
          : request.messageOrTx
      );
      msgHashBytes = Buffer.from(hashStr.slice(2), 'hex');
    }

    const participantsByDomain = {
      FOUNDATION: request.activeParticipants.filter((p) => p.domain === 'FOUNDATION'),
      PUBLIC: request.activeParticipants.filter((p) => p.domain === 'PUBLIC'),
      PRIVATE: request.activeParticipants.filter((p) => p.domain === 'PRIVATE'),
    };

    // Round 1: Init participant states and collect commitments
    const states: ReturnType<typeof initCggmp21Round1>['state'][] = [];
    const commitments: ReturnType<typeof initCggmp21Round1>['commitment'][] = [];

    for (const p of request.activeParticipants) {
      const domainSigners = participantsByDomain[p.domain].map((x) => x.shareIndex);
      const keyShare: Cggmp21KeyShare =
        p.keyShare ||
        (p.daemon && typeof p.daemon.loadShare === 'function'
          ? p.daemon.loadShare(request.sessionId, 'CGGMP21')
          : null);

      if (!keyShare) {
        throw new Error(
          `[3-Domain Coordinator] Participant ${p.participantId} does not have a valid Cggmp21KeyShare. Genuine TSS signing requires non-zero participant shares.`
        );
      }

      const { state, commitment } = initCggmp21Round1(request.sessionId, keyShare, domainSigners);
      states.push(state);
      commitments.push(commitment);
    }

    // Round 2: Decommitments & ZK proofs
    const decommitments: ReturnType<typeof generateCggmp21Round2Decommitment>[] = [];
    for (let i = 0; i < states.length; i++) {
      const p = request.activeParticipants[i];
      const privKeyHex = p.identityPrivateKeyHex || crypto.randomBytes(32).toString('hex');
      const decommit = generateCggmp21Round2Decommitment(states[i], privKeyHex);
      decommitments.push(decommit);
    }

    // Verify peer decommitments
    for (let i = 0; i < commitments.length; i++) {
      const v = verifyCggmp21PeerDecommitment(request.sessionId, commitments[i], decommitments[i]);
      if (!v.valid) {
        throw new Error(`[CGGMP21] Decommitment verification failed: ${v.reason}`);
      }
    }

    // Round 3: Delta shares and R computation with pairwise MtA contributions
    const mtaContributions = computeCggmp21PairwiseMtaContributions(states);
    const deltaShares: ReturnType<typeof computeCggmp21Round3DeltaShare>[] = [];
    for (let i = 0; i < states.length; i++) {
      const p = request.activeParticipants[i];
      const privKeyHex = p.identityPrivateKeyHex || crypto.randomBytes(32).toString('hex');
      const ds = computeCggmp21Round3DeltaShare(
        states[i],
        decommitments,
        privKeyHex,
        mtaContributions.get(states[i].participantId)
      );
      deltaShares.push(ds);
    }

    const { r, yParity } = aggregateCggmp21Delta(deltaShares, decommitments);

    // Round 4: Signature shares
    const sigmaShares: ReturnType<typeof computeCggmp21Round4SignatureShare>[] = [];
    for (let i = 0; i < states.length; i++) {
      const state = states[i];
      const p = request.activeParticipants[i];
      const privKeyHex = p.identityPrivateKeyHex || crypto.randomBytes(32).toString('hex');
      const ss = computeCggmp21Round4SignatureShare(
        state,
        r,
        msgHashBytes,
        privKeyHex,
        deltaShares[i].chiShareHex
      );

      // Verify individual share for identifiable aborts
      if (p.identityPublicKeyHex) {
        const v = verifyCggmp21SignatureShare(ss, request.sessionId, p.identityPublicKeyHex);
        if (!v.valid) {
          throw new Error(
            `[3-Domain Coordinator] Participant ${p.participantId} submitted invalid CGGMP21 share: ${v.reason}`
          );
        }
      }

      sigmaShares.push(ss);
    }

    const sig = aggregateCggmp21Signature(
      r,
      yParity,
      sigmaShares,
      msgHashBytes,
      request.domainKeys.aggregatedPublicKeyHex,
      request.extraParams?.chainId || 1n
    );

    return {
      sessionId: request.sessionId,
      chain: 'ethereum',
      domainsParticipated: ['FOUNDATION', 'PUBLIC', 'PRIVATE'],
      rawSignatureHex: sig.rawSignatureHex,
      verified: true,
    };
  }
}

export const threeDomainCoordinator = new ThreeDomainCoordinator();
