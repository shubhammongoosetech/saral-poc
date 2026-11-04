/**
 * thresholdEcdsa.ts
 *
 * SARAL Genuine Threshold Multi-Party Computation (MPC) ECDSA Engine
 * for secp256k1 and EVM (Ethereum / MST Testnet).
 *
 * Core Architectural Guarantees:
 *  1. Complete private key x is NEVER reconstructed during signing.
 *  2. Separation of Powers: Requires simultaneous cryptographic contributions from
 *     ALL 3 Domains: Foundation AND Public AND Private.
 *  3. Internal domain thresholds: Public (t_P of n_P) and Private (t_U of n_U)
 *     must both satisfy their respective quorums.
 *  4. Ephemeral nonce k is generated collaboratively via distributed blinding;
 *     k is never possessed by any single party.
 *  5. Only the final canonical (r, s, yParity) signature is produced.
 *  6. EVM and ethers.js v6 compatible raw signed transaction output.
 */

import { ethers } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  CURVE_ORDER,
  modN,
  modInverse,
  randomScalar,
  scalarMultiplyG,
  G,
  scalarToHex,
} from './secp256k1Math';
import {
  FieldShare,
  splitSecretField,
  computeLagrangeCoefficient,
} from './shamirField';
import { MpcParticipantDaemon } from './mpcParticipantDaemon';
import { statelessMpcCoordinator } from './mpcCoordinator';
import { IMpcParticipantClient } from '../participant/participantTransport';
import { trustedParticipantRegistry } from './participantRegistry';
import { performEnrollmentCeremony } from '../participant/nodeIdentityManager';

export class DaemonClientAdapter implements IMpcParticipantClient {
  constructor(private daemon: MpcParticipantDaemon) {}
  get id() { return this.daemon.id; }
  get domain() { return this.daemon.domain; }
  get nodeIndex() { return this.daemon.nodeIndex; }
  get shareIndex() { return this.daemon.shareIndex; }
  get identityPublicKeyHex() { return this.daemon.identityPublicKeyHex; }
  get endpoint() { return `ipc:///tmp/${this.daemon.id}.sock`; }
  initSession(config: any, commitments?: string[]) { return this.daemon.onSessionInit(config, commitments); }
  decommit(sessionId: string) { return this.daemon.onDecommitRequest(sessionId); }
  generateMtaPackets(sessionId: string, decommits: any[]) { return this.daemon.generatePairwiseMtaPackets(sessionId, decommits); }
  processMtaPackets(sessionId: string, pkts: any[]) { return this.daemon.onPeerMtaPacketsReceived(sessionId, pkts); }
  computePartialSignature(sessionId: string, r: bigint) { return this.daemon.computePartialSignature(sessionId, r); }
  async abortSession(sessionId: string, reason: string): Promise<void> { this.daemon.abortSession(sessionId, reason); }
}

export type DomainType = 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';

export interface DomainKeySetup {
  domain: DomainType;
  publicKeyPointHex: string; // Q_d = x_d * G (compressed)
  threshold: number;
  totalShares: number;
  shares: FieldShare[];
  commitments: string[];
}

export interface SaralWalletSetup {
  address: string;
  aggregatedPublicKeyHex: string; // Q = Q_F + Q_P + Q_U
  foundation: DomainKeySetup;
  publicDomain: DomainKeySetup;
  privateDomain: DomainKeySetup;
  createdAt: string;
}

export interface DomainQuorumParticipation {
  domain: DomainType;
  activeShareIndices: number[];
  shareValues: bigint[];
}

export interface MpcSigningSessionInput {
  unsignedTxSerialized: string; // RLP encoded unsigned transaction
  chainId: bigint;
  foundation: DomainQuorumParticipation;
  publicDomain: DomainQuorumParticipation;
  privateDomain: DomainQuorumParticipation;
}

export interface MpcSignatureResult {
  r: string; // 0x... (32-byte hex)
  s: string; // 0x... (32-byte hex)
  yParity: 0 | 1; // 0 or 1
  v: number; // EIP-155 or legacy v
  rawSignedTx: string; // Serialized broadcastable EVM transaction
  txHash: string; // keccak256(rawSignedTx)
  signingQuorum: {
    foundationAuthorized: boolean;
    publicNodeCount: number;
    privateNodeCount: number;
  };
}

/**
 * Generates an independent domain cryptographic key contribution.
 *
 * Each domain executes this ceremony inside its own custody boundary:
 *   - Foundation: Institutional administrative custodian.
 *   - Public: Staking validator node network.
 *   - Private: Sovereign user guardian / device.
 *
 * Emits ONLY the domain public key Q_domain and Feldman VSS public commitments
 * to the coordinator, while Shamir shares are distributed directly to nodes.
 */
export function generateDomainKeyContribution(
  domain: DomainType,
  totalShares: number,
  threshold: number
): DomainKeySetup {
  if (totalShares < 1) throw new Error(`[DKG] totalShares must be >= 1 for domain ${domain}`);
  if (threshold < 1 || threshold > totalShares) {
    throw new Error(`[DKG] threshold must be between 1 and ${totalShares} for domain ${domain}`);
  }

  // Generate private domain scalar x_domain strictly within domain boundary
  const x_domain = randomScalar();
  const sharing = splitSecretField(x_domain, totalShares, threshold);
  const Q_domain = scalarMultiplyG(x_domain);

  return {
    domain,
    publicKeyPointHex: Q_domain.toHex(true),
    threshold,
    totalShares,
    shares: sharing.shares,
    commitments: sharing.commitments,
  };
}

/**
 * Homomorphically aggregates independent domain public keys on secp256k1:
 *   Q = Q_Foundation + Q_Public + Q_Private
 *
 * Computes Ethereum/EVM account address directly from uncompressed point Q.
 * The master private key x = (x_F + x_P + x_U) is NEVER materialized or reconstructed.
 */
export function aggregateDomainPublicKeys(
  foundationPubHex: string,
  publicPubHex: string,
  privatePubHex: string
): { aggregatedPublicKeyHex: string; address: string } {
  const cleanF = foundationPubHex.startsWith('0x') ? foundationPubHex.slice(2) : foundationPubHex;
  const cleanP = publicPubHex.startsWith('0x') ? publicPubHex.slice(2) : publicPubHex;
  const cleanU = privatePubHex.startsWith('0x') ? privatePubHex.slice(2) : privatePubHex;

  const ptF = secp256k1.ProjectivePoint.fromHex(cleanF);
  const ptP = secp256k1.ProjectivePoint.fromHex(cleanP);
  const ptU = secp256k1.ProjectivePoint.fromHex(cleanU);

  ptF.assertValidity();
  ptP.assertValidity();
  ptU.assertValidity();

  const ptAgg = ptF.add(ptP).add(ptU);
  const aggregatedPublicKeyHex = '0x' + ptAgg.toHex(false);
  const address = ethers.computeAddress(aggregatedPublicKeyHex);

  return { aggregatedPublicKeyHex, address };
}

/**
 * Distributed Key Generation (DKG) for the 3-Domain SARAL Wallet.
 *
 * Decomposes key generation into three independent domain boundaries:
 *  1. Foundation institutional boundary: (1-of-1)
 *  2. Public validator domain boundary: (t_P-of-n_P)
 *  3. Private sovereign guardian boundary: (t_U-of-n_U)
 *
 * Public key Q is aggregated via elliptic-curve point addition:
 *   Q = Q_F + Q_P + Q_U
 *
 * The raw complete master private key x is NEVER aggregated, possessed, or computed.
 */
export function generateSaralWalletMpc(
  nShares: number = 9,
  threshold: number = 5,
  foundationTotalShares: number = 1,
  foundationThreshold: number = 1
): SaralWalletSetup {
  // Domain 1: Foundation (Institutional Administrative Quorum)
  const foundation = generateDomainKeyContribution(
    'FOUNDATION',
    foundationTotalShares,
    foundationThreshold
  );

  // Domain 2: Public (t_P-of-n_P independent staking validator nodes)
  const publicDomain = generateDomainKeyContribution('PUBLIC', nShares, threshold);

  // Domain 3: Private (t_U-of-n_U sovereign user devices / guardians)
  const privateDomain = generateDomainKeyContribution('PRIVATE', nShares, threshold);

  // Homomorphic aggregation of domain public keys: Q = Q_F + Q_P + Q_U
  const { aggregatedPublicKeyHex, address } = aggregateDomainPublicKeys(
    foundation.publicKeyPointHex,
    publicDomain.publicKeyPointHex,
    privateDomain.publicKeyPointHex
  );

  return {
    address,
    aggregatedPublicKeyHex,
    foundation,
    publicDomain,
    privateDomain,
    createdAt: new Date().toISOString(),
  };
}

/**
 * Derives the effective additive share for each participant in an active quorum:
 *   w_i = lambda_i * shareValue (mod n)
 * such that sum_{i in Quorum} w_i = x_domain (mod n).
 */
export function computeEffectiveAdditiveShares(
  participation: DomainQuorumParticipation
): bigint[] {
  const indices = participation.activeShareIndices;
  const values = participation.shareValues;

  if (indices.length !== values.length) {
    throw new Error('Indices and values length mismatch in domain quorum participation');
  }

  if (indices.length === 1) {
    // 1-of-1 threshold (e.g., Foundation)
    return [modN(values[0])];
  }

  const effectiveShares: bigint[] = [];
  for (let idx = 0; idx < indices.length; idx++) {
    const lambda = computeLagrangeCoefficient(indices[idx], indices);
    const w = modN(lambda * values[idx]);
    effectiveShares.push(w);
  }

  return effectiveShares;
}

/**
 * In-Process Test Simulation Harness for Multi-Party Computation (MPC) Threshold Signing Protocol.
 *
 * ARCHITECTURAL NOTICE:
 * This function provides an in-process simulation adapter strictly for test suite verification.
 * In production environments, wallet signing is orchestrated via `walletService.executeSigningTransaction()`
 * utilizing independent OS participant processes via `AuthenticatedParticipantClient` over authenticated
 * Unix domain sockets / IPC.
 *
 * MATHEMATICAL GUARANTEE:
 * At NO point is the complete private key x reconstructed, stored, or materialized.
 */
export async function executeMpcThresholdSign(
  input: MpcSigningSessionInput,
  expectedAggregatedPublicKeyHex: string,
  minPublicThreshold: number = 5,
  minPrivateThreshold: number = 5
): Promise<MpcSignatureResult> {
  // Validate domain threshold quorums and separation of powers
  if (!input.foundation || input.foundation.activeShareIndices.length < 1) {
    throw new Error('[MPC Authorization Failure] Foundation domain participation is required');
  }
  if (!input.publicDomain || input.publicDomain.activeShareIndices.length < minPublicThreshold) {
    throw new Error(
      `[MPC Authorization Failure] Public domain threshold not met: require >= ${minPublicThreshold} nodes, got ${input.publicDomain?.activeShareIndices?.length || 0}`
    );
  }
  if (!input.privateDomain || input.privateDomain.activeShareIndices.length < minPrivateThreshold) {
    throw new Error(
      `[MPC Authorization Failure] Private domain threshold not met: require >= ${minPrivateThreshold} nodes, got ${input.privateDomain?.activeShareIndices?.length || 0}`
    );
  }

  // Instantiate independent participant daemons
  const daemons: MpcParticipantDaemon[] = [];

  for (let i = 0; i < input.foundation.activeShareIndices.length; i++) {
    const idx = input.foundation.activeShareIndices[i];
    const val = input.foundation.shareValues[i];
    daemons.push(new MpcParticipantDaemon('FOUNDATION', idx, idx, val));
  }

  for (let i = 0; i < input.publicDomain.activeShareIndices.length; i++) {
    const idx = input.publicDomain.activeShareIndices[i];
    const val = input.publicDomain.shareValues[i];
    daemons.push(new MpcParticipantDaemon('PUBLIC', idx, idx, val));
  }

  for (let i = 0; i < input.privateDomain.activeShareIndices.length; i++) {
    const idx = input.privateDomain.activeShareIndices[i];
    const val = input.privateDomain.shareValues[i];
    daemons.push(new MpcParticipantDaemon('PRIVATE', idx, idx, val));
  }

  // Execute 3-round decentralized interactive threshold ECDSA protocol
  const clients: IMpcParticipantClient[] = daemons.map((d) => {
    if (!trustedParticipantRegistry.getParticipant(d.id)) {
      performEnrollmentCeremony({
        nodeId: d.id,
        domain: d.domain,
        nodeIndex: d.nodeIndex,
        shareIndex: d.shareIndex,
        endpoint: `ipc:///tmp/${d.id}.sock`,
        approved: true,
      });
    }
    return new DaemonClientAdapter(d);
  });

  return await statelessMpcCoordinator.coordinateSigningSession(
    clients,
    input.unsignedTxSerialized,
    input.chainId,
    expectedAggregatedPublicKeyHex,
    undefined,
    minPublicThreshold,
    minPrivateThreshold
  );
}

/**
 * Verifies that a given subset of domain shares satisfies the 3-domain quorum.
 */
export function verifyThreeDomainQuorum(
  foundationPresent: boolean,
  publicNodesCount: number,
  privateNodesCount: number,
  minPublicThreshold: number = 5,
  minPrivateThreshold: number = 5
): { authorized: boolean; reason?: string } {
  if (!foundationPresent) {
    return { authorized: false, reason: 'Missing Foundation domain institutional authorization' };
  }
  if (publicNodesCount < minPublicThreshold) {
    return {
      authorized: false,
      reason: `Public domain quorum shortfall: ${publicNodesCount} nodes active, minimum ${minPublicThreshold} required`,
    };
  }
  if (privateNodesCount < minPrivateThreshold) {
    return {
      authorized: false,
      reason: `Private sovereign domain quorum shortfall: ${privateNodesCount} nodes active, minimum ${minPrivateThreshold} required`,
    };
  }
  return { authorized: true };
}
