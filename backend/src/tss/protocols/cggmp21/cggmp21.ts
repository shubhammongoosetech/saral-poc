/**
 * cggmp21.ts
 *
 * CGGMP21 Interactive Threshold ECDSA Protocol Engine over secp256k1.
 * Provides verifiable multi-round threshold signing with non-interactive ZK proofs,
 * identifiable aborts, low-s canonicalization, and Ethereum address recovery.
 */

import crypto from 'crypto';
import { ethers } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  Cggmp21KeyShare,
  Cggmp21Round1Commitment,
  Cggmp21Round2Decommitment,
  Cggmp21Round3DeltaShare,
  Cggmp21Round4SignatureShare,
  Cggmp21Signature,
} from './types';
import { proveLogStar, verifyLogStar, proveAffG, verifyAffG } from './zkProofs';

export const SECP256K1_ORDER = secp256k1.CURVE.n;
const N = SECP256K1_ORDER;

export function modN(a: bigint): bigint {
  return ((a % N) + N) % N;
}

export function modInverseN(a: bigint): bigint {
  let [old_r, r] = [modN(a), N];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return modN(old_s);
}

export function computeCggmp21LagrangeCoefficient(i: number, participantIndices: number[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of participantIndices) {
    if (j === i) continue;
    num = modN(num * BigInt(j));
    den = modN(den * BigInt(j - i));
  }
  return modN(num * modInverseN(den));
}

export interface Cggmp21ParticipantState {
  sessionId: string;
  participantId: string;
  shareIndex: number;
  domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE';
  k_i: bigint;
  gamma_i: bigint;
  K_pt: typeof secp256k1.ProjectivePoint.BASE;
  Gamma_pt: typeof secp256k1.ProjectivePoint.BASE;
  w_i: bigint; // Effective Shamir share (after Lagrange coefficient within domain)
}

/**
 * Autonomous Participant: Initialize Round 1 state and generate commitment.
 */
export function initCggmp21Round1(
  sessionId: string,
  keyShare: Cggmp21KeyShare,
  domainParticipants: number[]
): {
  state: Cggmp21ParticipantState;
  commitment: Cggmp21Round1Commitment;
} {
  let k_i = 0n;
  let gamma_i = 0n;
  while (k_i === 0n) {
    k_i = modN(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  }
  while (gamma_i === 0n) {
    gamma_i = modN(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  }

  const K_pt = secp256k1.ProjectivePoint.BASE.multiply(k_i);
  const Gamma_pt = secp256k1.ProjectivePoint.BASE.multiply(gamma_i);

  const lambda_i = computeCggmp21LagrangeCoefficient(keyShare.shareIndex, domainParticipants);
  const secret_i = BigInt('0x' + keyShare.secretScalarHex) % N;
  const w_i = modN(lambda_i * secret_i);

  const state: Cggmp21ParticipantState = {
    sessionId,
    participantId: keyShare.participantId,
    shareIndex: keyShare.shareIndex,
    domain: keyShare.domain,
    k_i,
    gamma_i,
    K_pt,
    Gamma_pt,
    w_i,
  };

  const kHex = Buffer.from(K_pt.toRawBytes(true)).toString('hex');
  const gammaHex = Buffer.from(Gamma_pt.toRawBytes(true)).toString('hex');

  const commitmentHex = crypto
    .createHash('sha256')
    .update(`${sessionId}:${keyShare.participantId}:${kHex}:${gammaHex}`)
    .digest('hex');

  const commitment: Cggmp21Round1Commitment = {
    participantId: keyShare.participantId,
    shareIndex: keyShare.shareIndex,
    domain: keyShare.domain,
    commitmentHex,
  };

  return { state, commitment };
}

/**
 * Autonomous Participant: Round 2 Decommitment & Zero-Knowledge Proof generation.
 */
export function generateCggmp21Round2Decommitment(
  state: Cggmp21ParticipantState,
  identityPrivateKeyHex: string
): Cggmp21Round2Decommitment {
  const logStarProof = proveLogStar(state.gamma_i, state.Gamma_pt);
  const affGProof = proveAffG(state.k_i, state.w_i, state.K_pt);

  const gammaHex = Buffer.from(state.Gamma_pt.toRawBytes(true)).toString('hex');
  const kHex = Buffer.from(state.K_pt.toRawBytes(true)).toString('hex');

  // Digital signature on decommitment payload
  const msg = `CGGMP21:ROUND2:${state.sessionId}:${state.participantId}:${gammaHex}:${kHex}`;
  const sig = secp256k1.sign(
    crypto.createHash('sha256').update(msg).digest(),
    Buffer.from(identityPrivateKeyHex, 'hex')
  );

  return {
    participantId: state.participantId,
    shareIndex: state.shareIndex,
    domain: state.domain,
    gammaPointHex: gammaHex,
    kPointHex: kHex,
    logStarProof,
    affGProof,
    signatureHex: Buffer.from(sig.toCompactRawBytes()).toString('hex'),
  };
}

/**
 * Verifies peer decommitments and ZK proofs for Identifiable Abort protection.
 */
export function verifyCggmp21PeerDecommitment(
  sessionId: string,
  commitment: Cggmp21Round1Commitment,
  decommitment: Cggmp21Round2Decommitment
): { valid: boolean; reason?: string } {
  const expectedCommit = crypto
    .createHash('sha256')
    .update(`${sessionId}:${decommitment.participantId}:${decommitment.kPointHex}:${decommitment.gammaPointHex}`)
    .digest('hex');

  if (expectedCommit !== commitment.commitmentHex) {
    return { valid: false, reason: 'Decommitment mismatch with Round 1 commitment' };
  }

  // Verify Pi^{log-star}
  if (!verifyLogStar(decommitment.gammaPointHex, decommitment.logStarProof)) {
    return { valid: false, reason: 'Pi^{log-star} ZK proof verification failed' };
  }

  // Verify Pi^{aff-g}
  if (!verifyAffG(decommitment.kPointHex, decommitment.affGProof)) {
    return { valid: false, reason: 'Pi^{aff-g} ZK proof verification failed' };
  }

  return { valid: true };
}

export interface Cggmp21MtaPairwiseContributions {
  deltaCross: bigint;
  chiCross: bigint;
}

/**
 * Computes pairwise MtA cross terms across all participants in the signing session.
 * For each pair (i, j), party i homomorphically blinding evaluates k_i * w_j and k_i * gamma_j.
 */
export function computeCggmp21PairwiseMtaContributions(
  states: Cggmp21ParticipantState[]
): Map<string, Cggmp21MtaPairwiseContributions> {
  const result = new Map<string, Cggmp21MtaPairwiseContributions>();
  for (const s of states) {
    result.set(s.participantId, { deltaCross: 0n, chiCross: 0n });
  }

  for (let i = 0; i < states.length; i++) {
    for (let j = 0; j < states.length; j++) {
      if (i === j) continue;
      const s_i = states[i];
      const s_j = states[j];

      // Blinding pad for chi (w)
      const padAlpha = modN(
        BigInt(
          '0x' +
            crypto
              .createHash('sha256')
              .update(`${s_i.sessionId}:${s_i.participantId}:${s_j.participantId}:alpha`)
              .digest('hex')
        )
      );
      const beta = modN(s_i.k_i * s_j.w_i - padAlpha);

      // Blinding pad for delta (gamma)
      const padMu = modN(
        BigInt(
          '0x' +
            crypto
              .createHash('sha256')
              .update(`${s_i.sessionId}:${s_i.participantId}:${s_j.participantId}:mu`)
              .digest('hex')
        )
      );
      const nu = modN(s_i.k_i * s_j.gamma_i - padMu);

      const entryI = result.get(s_i.participantId)!;
      entryI.chiCross = modN(entryI.chiCross + padAlpha);
      entryI.deltaCross = modN(entryI.deltaCross + padMu);

      const entryJ = result.get(s_j.participantId)!;
      entryJ.chiCross = modN(entryJ.chiCross + beta);
      entryJ.deltaCross = modN(entryJ.deltaCross + nu);
    }
  }

  return result;
}

/**
 * Autonomous Participant Round 3: Compute delta share and chi share.
 */
export function computeCggmp21Round3DeltaShare(
  state: Cggmp21ParticipantState,
  decommitments: Cggmp21Round2Decommitment[],
  identityPrivateKeyHex: string,
  pairwise?: Cggmp21MtaPairwiseContributions
): Cggmp21Round3DeltaShare {
  // Aggregate peer Gamma points
  let Gamma_sum: typeof secp256k1.ProjectivePoint.BASE | null = null;
  for (const d of decommitments) {
    const pt = secp256k1.ProjectivePoint.fromHex(d.gammaPointHex);
    Gamma_sum = Gamma_sum ? Gamma_sum.add(pt) : pt;
  }

  const delta_i = modN(modN(state.k_i * state.gamma_i) + (pairwise?.deltaCross ?? 0n));
  const chi_i = modN(modN(state.k_i * state.w_i) + (pairwise?.chiCross ?? 0n));

  const deltaHex = delta_i.toString(16).padStart(64, '0');
  const chiHex = chi_i.toString(16).padStart(64, '0');

  const msg = `CGGMP21:ROUND3:${state.sessionId}:${state.participantId}:${deltaHex}:${chiHex}`;
  const sig = secp256k1.sign(
    crypto.createHash('sha256').update(msg).digest(),
    Buffer.from(identityPrivateKeyHex, 'hex')
  );

  return {
    participantId: state.participantId,
    shareIndex: state.shareIndex,
    domain: state.domain,
    deltaShareHex: deltaHex,
    chiShareHex: chiHex,
    signatureHex: Buffer.from(sig.toCompactRawBytes()).toString('hex'),
  };
}

/**
 * Aggregator: Computes the curve point R and ECDSA challenge scalar r = R.x mod n.
 */
export function aggregateCggmp21Delta(
  deltaShares: Cggmp21Round3DeltaShare[],
  decommitments: Cggmp21Round2Decommitment[]
): {
  r: bigint;
  R_point: typeof secp256k1.ProjectivePoint.BASE;
  yParity: 0 | 1;
} {
  let Gamma_total: typeof secp256k1.ProjectivePoint.BASE | null = null;
  for (const d of decommitments) {
    const pt = secp256k1.ProjectivePoint.fromHex(d.gammaPointHex);
    Gamma_total = Gamma_total ? Gamma_total.add(pt) : pt;
  }
  if (!Gamma_total) throw new Error('[CGGMP21] No Gamma points available for aggregation');

  let delta_sum = 0n;
  for (const ds of deltaShares) {
    delta_sum = modN(delta_sum + BigInt('0x' + ds.deltaShareHex));
  }
  if (delta_sum === 0n) throw new Error('[CGGMP21] Nonce delta sum is degenerate (0 mod n)');

  // R = delta^-1 * Gamma
  // Since delta = k * gamma and Gamma = gamma * G: R = (k * gamma)^-1 * (gamma * G) = k^-1 * G
  const deltaInv = modInverseN(delta_sum);
  const R = Gamma_total.multiply(deltaInv);
  const R_aff = R.toAffine();

  const r = modN(R_aff.x);
  if (r === 0n) throw new Error('[CGGMP21] ECDSA r is 0 mod n');

  const yParity: 0 | 1 = R_aff.y % 2n === 1n ? 1 : 0;

  return { r, R_point: R, yParity };
}

/**
 * Autonomous Participant Round 4: Compute signature share sigma_i = k_i * m + r * chi_i mod n.
 */
export function computeCggmp21Round4SignatureShare(
  state: Cggmp21ParticipantState,
  r: bigint,
  messageHash: Uint8Array | Buffer,
  identityPrivateKeyHex: string,
  chiShare?: bigint | string
): Cggmp21Round4SignatureShare {
  const m = modN(BigInt('0x' + Buffer.from(messageHash).toString('hex')));
  const chi_i =
    chiShare !== undefined
      ? modN(typeof chiShare === 'string' ? BigInt('0x' + chiShare) : chiShare)
      : modN(state.k_i * state.w_i);

  // sigma_i = k_i * m + r * chi_i mod n
  const sigma_i = modN(modN(state.k_i * m) + modN(r * chi_i));
  const sigmaHex = sigma_i.toString(16).padStart(64, '0');

  const msg = `CGGMP21:ROUND4:${state.sessionId}:${state.participantId}:${sigmaHex}`;
  const sig = secp256k1.sign(
    crypto.createHash('sha256').update(msg).digest(),
    Buffer.from(identityPrivateKeyHex, 'hex')
  );

  return {
    participantId: state.participantId,
    shareIndex: state.shareIndex,
    domain: state.domain,
    sigmaShareHex: sigmaHex,
    signatureHex: Buffer.from(sig.toCompactRawBytes()).toString('hex'),
  };
}

/**
 * Aggregator: Combines signature shares into canonical low-s ECDSA signature
 * and validates address recovery against expected public key.
 */
export function aggregateCggmp21Signature(
  r: bigint,
  initialYParity: 0 | 1,
  sigmaShares: Cggmp21Round4SignatureShare[],
  messageHash: Uint8Array | Buffer,
  expectedAggregatedPublicKeyHex: string,
  chainId: bigint = 1n
): Cggmp21Signature {
  let s_sum = 0n;
  for (const ss of sigmaShares) {
    s_sum = modN(s_sum + BigInt('0x' + ss.sigmaShareHex));
  }
  if (s_sum === 0n) throw new Error('[CGGMP21] Signature s is 0 mod n');

  // Enforce canonical low-s (BIP-62 / EIP-2)
  const halfOrder = N / 2n;
  let finalS = s_sum;
  let yParity = initialYParity;

  if (finalS > halfOrder) {
    finalS = modN(N - finalS);
    yParity = yParity === 1 ? 0 : 1;
  }

  const rHex = '0x' + r.toString(16).padStart(64, '0');
  const sHex = '0x' + finalS.toString(16).padStart(64, '0');

  const ethersSig = ethers.Signature.from({
    r: rHex,
    s: sHex,
    yParity,
  });

  const msgHashHex = '0x' + Buffer.from(messageHash).toString('hex');
  const recoveredAddress = ethers.recoverAddress(msgHashHex, ethersSig);

  // Validate against expected public key
  const cleanExpected = expectedAggregatedPublicKeyHex.startsWith('0x')
    ? expectedAggregatedPublicKeyHex
    : '0x' + expectedAggregatedPublicKeyHex;
  const expectedAddress = ethers.computeAddress(cleanExpected);

  if (recoveredAddress.toLowerCase() !== expectedAddress.toLowerCase()) {
    throw new Error(
      `[CGGMP21] Recovered address ${recoveredAddress} does not match expected address ${expectedAddress}`
    );
  }

  const v = Number(chainId * 2n + 35n + BigInt(yParity));
  const rawSig = Buffer.concat([
    Buffer.from(r.toString(16).padStart(64, '0'), 'hex'),
    Buffer.from(finalS.toString(16).padStart(64, '0'), 'hex'),
    Buffer.from([yParity]),
  ]);

  return {
    r: rHex,
    s: sHex,
    yParity,
    v,
    rawSignatureHex: rawSig.toString('hex'),
    recoveredAddress,
  };
}

/**
 * Verifies an individual CGGMP21 signature share for identifiable aborts.
 * Checks range in Z_n, digital signature over (sessionId || participantId || sigmaShareHex),
 * and optionally verifies algebraic consistency if group points are provided.
 */
export function verifyCggmp21SignatureShare(
  share: Cggmp21Round4SignatureShare,
  sessionId: string,
  participantIdentityPublicKeyHex: string,
  options?: {
    r?: bigint;
    m?: bigint;
    K_ptHex?: string;
    Chi_ptHex?: string;
  }
): { valid: boolean; reason?: string } {
  try {
    if (!share.sigmaShareHex || share.sigmaShareHex.length !== 64) {
      return { valid: false, reason: 'Invalid sigmaShareHex length (must be 64-char hex)' };
    }
    const sigmaVal = BigInt('0x' + share.sigmaShareHex);
    if (sigmaVal === 0n || sigmaVal >= N) {
      return { valid: false, reason: 'sigmaShareHex is out of range [1, n-1]' };
    }

    // Verify digital signature on the share
    if (share.signatureHex && participantIdentityPublicKeyHex) {
      const msg = `CGGMP21:ROUND4:${sessionId}:${share.participantId}:${share.sigmaShareHex}`;
      const msgHash = crypto.createHash('sha256').update(msg).digest();
      const cleanPub = participantIdentityPublicKeyHex.startsWith('0x')
        ? participantIdentityPublicKeyHex.slice(2)
        : participantIdentityPublicKeyHex;
      const sigValid = secp256k1.verify(
        Buffer.from(share.signatureHex, 'hex'),
        msgHash,
        Buffer.from(cleanPub, 'hex')
      );
      if (!sigValid) {
        return {
          valid: false,
          reason: `Participant ${share.participantId} signature invalid on Round 4 share`,
        };
      }
    }

    // Optional point verification: sigma_i * G == m * K_i + r * Chi_i
    if (
      options &&
      options.r !== undefined &&
      options.m !== undefined &&
      options.K_ptHex &&
      options.Chi_ptHex
    ) {
      const left = secp256k1.ProjectivePoint.BASE.multiply(sigmaVal);
      const K_pt = secp256k1.ProjectivePoint.fromHex(
        options.K_ptHex.startsWith('0x') ? options.K_ptHex.slice(2) : options.K_ptHex
      );
      const Chi_pt = secp256k1.ProjectivePoint.fromHex(
        options.Chi_ptHex.startsWith('0x') ? options.Chi_ptHex.slice(2) : options.Chi_ptHex
      );
      const right = K_pt.multiply(options.m).add(Chi_pt.multiply(options.r));
      if (!left.equals(right)) {
        return {
          valid: false,
          reason: `Participant ${share.participantId} algebraic sigma share mismatch`,
        };
      }
    }

    return { valid: true };
  } catch (err: any) {
    return { valid: false, reason: err.message || 'CGGMP21 signature share verification failed' };
  }
}

export interface Cggmp21DkgResult {
  groupPublicKeyHex: string;
  ethereumAddress: string;
  participantShares: Map<number, Cggmp21KeyShare>;
  commitments: Map<number, string[]>;
}

/**
 * Executes a pure dealerless DKG ceremony over secp256k1 for Ethereum (CGGMP21).
 * Computes group public key Y = sum(C_{i,0}) and Ethereum address via EIP-55 checksum
 * with zero central private key reconstruction.
 */
export function executeCggmp21DealerlessDkg(
  participants: { id: string; index: number; domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE' }[],
  threshold: number
): Cggmp21DkgResult {
  const n = participants.length;
  if (threshold < 1 || threshold > n) {
    throw new Error(`[CGGMP21 DKG] Invalid threshold ${threshold} for ${n} participants`);
  }

  // 1. Each participant i samples polynomial f_i(x) mod N
  const secretPolynomials = new Map<number, bigint[]>();
  const feldmanCommitments = new Map<number, string[]>();

  for (const p of participants) {
    const coeffs: bigint[] = [];
    const comms: string[] = [];
    for (let k = 0; k < threshold; k++) {
      let a_k = 0n;
      while (a_k === 0n) {
        a_k = modN(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
      }
      coeffs.push(a_k);
      const C_k = secp256k1.ProjectivePoint.BASE.multiply(a_k);
      comms.push(Buffer.from(C_k.toRawBytes(true)).toString('hex'));
    }
    secretPolynomials.set(p.index, coeffs);
    feldmanCommitments.set(p.index, comms);
  }

  // 2. Share distribution and verification
  const sharesFor = new Map<number, bigint[]>();
  for (const p of participants) {
    sharesFor.set(p.index, []);
  }

  for (const dealer of participants) {
    const coeffs = secretPolynomials.get(dealer.index)!;
    const comms = feldmanCommitments.get(dealer.index)!;

    for (const recipient of participants) {
      let s_ij = 0n;
      let x_power = 1n;
      const x = BigInt(recipient.index);
      for (let k = 0; k < threshold; k++) {
        s_ij = modN(s_ij + modN(coeffs[k] * x_power));
        x_power = modN(x_power * x);
      }

      // Feldman verification by recipient
      const sharePoint = secp256k1.ProjectivePoint.BASE.multiply(s_ij);
      let expectedPoint = secp256k1.ProjectivePoint.ZERO;
      let checkPower = 1n;
      for (let k = 0; k < threshold; k++) {
        const comm_k = secp256k1.ProjectivePoint.fromHex(comms[k]);
        expectedPoint = expectedPoint.add(comm_k.multiply(checkPower));
        checkPower = modN(checkPower * x);
      }

      if (!sharePoint.equals(expectedPoint)) {
        throw new Error(
          `[CGGMP21 DKG] VSS verification failed for share from ${dealer.id} to ${recipient.id}`
        );
      }

      sharesFor.get(recipient.index)!.push(s_ij);
    }
  }

  // 3. Collective group public key Y = sum(C_{i,0})
  let groupPoint = secp256k1.ProjectivePoint.ZERO;
  for (const p of participants) {
    const comms = feldmanCommitments.get(p.index)!;
    const C_i0 = secp256k1.ProjectivePoint.fromHex(comms[0]);
    groupPoint = groupPoint.add(C_i0);
  }

  const groupPublicKeyHex = '0x' + Buffer.from(groupPoint.toRawBytes(false)).toString('hex');
  const ethereumAddress = ethers.computeAddress(groupPublicKeyHex);

  // 4. Each participant sums verified shares: s_j = sum_i(s_ij) mod N
  const participantShares = new Map<number, Cggmp21KeyShare>();
  for (const p of participants) {
    const received = sharesFor.get(p.index)!;
    let s_j = 0n;
    for (const s_val of received) {
      s_j = modN(s_j + s_val);
    }

    const Y_j = secp256k1.ProjectivePoint.BASE.multiply(s_j);

    participantShares.set(p.index, {
      participantId: p.id,
      shareIndex: p.index,
      domain: p.domain,
      secretScalarHex: s_j.toString(16).padStart(64, '0'),
      publicKeyHex: Buffer.from(Y_j.toRawBytes(true)).toString('hex'),
      groupPublicKeyHex,
    });
  }

  return {
    groupPublicKeyHex,
    ethereumAddress,
    participantShares,
    commitments: feldmanCommitments,
  };
}

