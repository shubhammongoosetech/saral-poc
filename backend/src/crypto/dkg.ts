/**
 * dkg.ts
 *
 * SARAL Distributed Key Generation (DKG) per Trust Domain
 *
 * Architecture (Feldman VSS / GG18-compatible, Decisions D-01):
 *   Each node i in domain d independently:
 *     1. Samples polynomial f_{d,i}(z) = a_{d,i,0} + a_{d,i,1}*z + ... + a_{d,i,t-1}*z^{t-1} mod n
 *     2. Broadcasts public commitments C_{d,i,k} = a_{d,i,k} * G  (k = 0..t-1)
 *     3. Distributes sub-share s_{d,i,j} = f_{d,i}(j) to each peer node j (private channel)
 *     4. Each node j accumulates its final domain share: S_{d,j} = Σ_i f_{d,i}(j) mod n
 *
 *   Domain public key: Q_d = Σ_i C_{d,i,0}  (sum of constant-term commitments)
 *   Aggregate wallet public key: Q = Q_F + Q_P + Q_V
 *
 *   THE DOMAIN SECRET x_d = Σ_i a_{d,i,0} IS NEVER COMPUTED BY ANY PARTY.
 *   It exists only as a mathematical sum of independent random contributions.
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { CURVE_ORDER, modN, randomScalar, scalarMultiplyG } from './secp256k1Math';
import { evaluatePolynomial } from './shamirField';
import type { DomainType } from './thresholdEcdsa';

export interface NodeDkgContribution {
  nodeId: string;         // Contributor node ID
  commitments: string[];  // C_{d,i,k} = a_{d,i,k} * G  (compressed hex, length = threshold)
  subShares: Map<string, bigint>; // nodeId → f_{d,i}(nodeIndex)
}

export interface NodeDkgLocalState {
  nodeId: string;
  domain: DomainType;
  nodeIndex: number;      // 1-based index in domain
  threshold: number;
  totalNodes: number;
  // Secret polynomial coefficients (NEVER exported)
  _secretCoeffs: bigint[];
  commitments: string[];  // Public Feldman commitments
}

export interface DkgResult {
  domain: DomainType;
  domainPublicKeyHex: string;        // Q_d = Σ C_{d,i,0}
  nodeShares: Map<string, bigint>;   // nodeId → S_{d,j} (each node's accumulated share)
  allCommitments: Map<string, string[]>; // nodeId → their commitments
  threshold: number;
  totalNodes: number;
}

/**
 * Phase 1 (per node): Each node generates its local polynomial and commitments.
 * The secret coefficients are stored in-memory in the node's local state only.
 * NEVER export _secretCoeffs from this object.
 */
export function dkgPhase1_generateContribution(
  nodeId: string,
  domain: DomainType,
  nodeIndex: number,
  threshold: number,
  totalNodes: number
): NodeDkgLocalState {
  if (threshold < 1 || threshold > totalNodes) {
    throw new Error(`[DKG] Invalid threshold ${threshold} for ${totalNodes} nodes in ${domain}`);
  }
  if (totalNodes < 3) {
    throw new Error(`[DKG] Domain ${domain} requires at least 3 nodes (D-02)`);
  }

  // Generate t random coefficients: a_{d,i,0} = random secret contribution, a_{d,i,1..t-1} = random
  const secretCoeffs: bigint[] = [];
  for (let k = 0; k < threshold; k++) {
    secretCoeffs.push(randomScalar());
  }

  // Compute Feldman commitments C_{d,i,k} = a_{d,i,k} * G
  const commitments: string[] = secretCoeffs.map(c => {
    const pt = scalarMultiplyG(c);
    return pt.toHex(true);
  });

  return {
    nodeId,
    domain,
    nodeIndex,
    threshold,
    totalNodes,
    _secretCoeffs: secretCoeffs,
    commitments,
  };
}

/**
 * Phase 1 (per node): Compute sub-shares to distribute to all other nodes.
 * sub-share for peer j = f_{d,i}(j), where j is the peer's nodeIndex.
 * MUST be sent over a secure channel to peer j.
 */
export function dkgPhase1_computeSubShares(
  localState: NodeDkgLocalState,
  peerIndices: number[] // 1-based indices of all nodes in the domain
): Map<number, bigint> {
  const subShares = new Map<number, bigint>();
  for (const j of peerIndices) {
    const share = evaluatePolynomial(localState._secretCoeffs, BigInt(j));
    subShares.set(j, share);
  }
  return subShares;
}

/**
 * Phase 2 (per node): Verify received sub-share from contributor i, using their commitments.
 * Check: s_{d,i,j} * G == Σ_{k=0}^{t-1} j^k * C_{d,i,k}
 */
export function dkgPhase2_verifySubShare(
  subShare: bigint,
  fromNodeCommitments: string[],
  recipientIndex: number,  // j (1-based)
  threshold: number
): boolean {
  if (fromNodeCommitments.length !== threshold) return false;

  // Compute expected point: Σ_{k=0}^{t-1} j^k * C_{d,i,k}
  let expectedPoint: ReturnType<typeof secp256k1.ProjectivePoint.fromHex> | null = null;
  let jPow = 1n;
  const j = BigInt(recipientIndex);

  for (let k = 0; k < threshold; k++) {
    const commitment = fromNodeCommitments[k];
    const cleanHex = commitment.startsWith('0x') ? commitment.slice(2) : commitment;
    const commitPoint = secp256k1.ProjectivePoint.fromHex(cleanHex);
    const term = commitPoint.multiply(modN(jPow));
    expectedPoint = expectedPoint ? expectedPoint.add(term) : term;
    jPow = modN(jPow * j);
  }

  // Compute actual point: subShare * G
  if (subShare <= 0n || subShare >= CURVE_ORDER) return false;
  const actualPoint = scalarMultiplyG(subShare);

  if (!expectedPoint) return false;

  // Compare affine coordinates
  const actual = actualPoint.toAffine();
  const expected = expectedPoint.toAffine();
  return actual.x === expected.x && actual.y === expected.y;
}

/**
 * Phase 3 (per node): Accumulate all verified sub-shares into the node's final domain share.
 * S_{d,j} = Σ_i s_{d,i,j} mod n
 * This is the node's permanent share of the domain secret. It is NEVER the full domain secret.
 */
export function dkgPhase3_accumulateShares(
  verifiedSubShares: bigint[] // one per contributing node
): bigint {
  let accumulated = 0n;
  for (const share of verifiedSubShares) {
    accumulated = modN(accumulated + share);
  }
  if (accumulated === 0n) {
    throw new Error('[DKG] Accumulated share is zero — this is cryptographically invalid');
  }
  return accumulated;
}

/**
 * Computes the domain public key from all nodes' Feldman commitment constant terms.
 * Q_d = Σ_i C_{d,i,0}  (sum of first commitments from each contributor)
 * This is computed WITHOUT any secret scalar.
 */
export function dkgComputeDomainPublicKey(
  allNodeCommitments: Map<string, string[]> // nodeId → commitments
): string {
  let domainPublicKey: ReturnType<typeof secp256k1.ProjectivePoint.fromHex> | null = null;

  for (const [, commitments] of allNodeCommitments) {
    if (commitments.length === 0) throw new Error('[DKG] Empty commitments array');
    const c0 = commitments[0];
    const cleanHex = c0.startsWith('0x') ? c0.slice(2) : c0;
    const point = secp256k1.ProjectivePoint.fromHex(cleanHex);
    domainPublicKey = domainPublicKey ? domainPublicKey.add(point) : point;
  }

  if (!domainPublicKey) throw new Error('[DKG] No commitments provided');
  return domainPublicKey.toHex(true);
}

/**
 * Full in-process DKG simulation for testing.
 * In production, phases 1-3 happen across separate node processes.
 * This function simulates the complete protocol without any node seeing x_d.
 */
export function runDomainDkgSimulation(
  domain: DomainType,
  nodeIds: string[],     // ordered list of node IDs
  threshold: number
): DkgResult {
  const totalNodes = nodeIds.length;
  if (totalNodes < 3) throw new Error(`[DKG] Need at least 3 nodes, got ${totalNodes}`);

  // Phase 1: Each node generates its polynomial and commitments
  const localStates = new Map<string, NodeDkgLocalState>();
  for (let i = 0; i < totalNodes; i++) {
    const state = dkgPhase1_generateContribution(
      nodeIds[i], domain, i + 1, threshold, totalNodes
    );
    localStates.set(nodeIds[i], state);
  }

  // Phase 1: Each node computes sub-shares for all peers
  const allSubShares = new Map<string, Map<number, bigint>>(); // contributorId → {peerIndex → subShare}
  const peerIndices = Array.from({ length: totalNodes }, (_, i) => i + 1);
  for (const [nodeId, state] of localStates) {
    const subShares = dkgPhase1_computeSubShares(state, peerIndices);
    allSubShares.set(nodeId, subShares);
  }

  // Phase 2 + 3: Each node j receives and verifies sub-shares, then accumulates
  const nodeShares = new Map<string, bigint>();
  for (let j = 0; j < totalNodes; j++) {
    const recipientId = nodeIds[j];
    const recipientIndex = j + 1;
    const verifiedSubShares: bigint[] = [];

    for (const contributorId of nodeIds) {
      const contributorState = localStates.get(contributorId)!;
      const subShare = allSubShares.get(contributorId)!.get(recipientIndex)!;

      // Verify sub-share against commitments
      const valid = dkgPhase2_verifySubShare(
        subShare,
        contributorState.commitments,
        recipientIndex,
        threshold
      );
      if (!valid) {
        throw new Error(`[DKG] Sub-share verification failed: contributor ${contributorId} → recipient ${recipientId}`);
      }
      verifiedSubShares.push(subShare);
    }

    const finalShare = dkgPhase3_accumulateShares(verifiedSubShares);
    nodeShares.set(recipientId, finalShare);
  }

  // Collect all commitments
  const allCommitments = new Map<string, string[]>();
  for (const [nodeId, state] of localStates) {
    allCommitments.set(nodeId, state.commitments);
    // WIPE secret coefficients
    state._secretCoeffs.fill(0n);
  }

  // Compute domain public key
  const domainPublicKeyHex = dkgComputeDomainPublicKey(allCommitments);

  return {
    domain,
    domainPublicKeyHex,
    nodeShares,
    allCommitments,
    threshold,
    totalNodes,
  };
}

/**
 * Runs DKG across all 3 domains and computes the aggregate wallet public key.
 * Q = Q_F + Q_P + Q_V
 * The private key x = x_F + x_P + x_V is NEVER computed.
 */
export function runFullSaralDkg(
  foundationNodeIds: string[],
  publicNodeIds: string[],
  privateNodeIds: string[],
  thresholds: { foundation: number; public: number; private: number }
): {
  foundationDkg: DkgResult;
  publicDkg: DkgResult;
  privateDkg: DkgResult;
  aggregatePublicKeyHex: string;
} {
  const foundationDkg = runDomainDkgSimulation('FOUNDATION', foundationNodeIds, thresholds.foundation);
  const publicDkg = runDomainDkgSimulation('PUBLIC', publicNodeIds, thresholds.public);
  const privateDkg = runDomainDkgSimulation('PRIVATE', privateNodeIds, thresholds.private);

  // Aggregate public key: Q = Q_F + Q_P + Q_V
  const getPoint = (hex: string) => {
    const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
    return secp256k1.ProjectivePoint.fromHex(clean);
  };

  const Q_F = getPoint(foundationDkg.domainPublicKeyHex);
  const Q_P = getPoint(publicDkg.domainPublicKeyHex);
  const Q_V = getPoint(privateDkg.domainPublicKeyHex);
  const Q = Q_F.add(Q_P).add(Q_V);
  const aggregatePublicKeyHex = Q.toHex(true);

  return { foundationDkg, publicDkg, privateDkg, aggregatePublicKeyHex };
}
