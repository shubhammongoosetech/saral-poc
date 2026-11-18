/**
 * frostTaproot.ts
 *
 * BIP-340 / BIP-341 Taproot-compatible FROST over secp256k1 for Bitcoin.
 *
 * Mathematical Invariants:
 *  - Curve: secp256k1 (y^2 = x^3 + 7 over F_p)
 *  - Order: n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
 *  - BIP-340 Tagged Hashes: SHA256(SHA256(tag) || SHA256(tag) || msg)
 *  - Parity handling: BIP-340 requires x-only public keys and even-Y curve points.
 *    If P.y is odd, the secret key scalar is negated mod n.
 *  - Taproot tweaking (BIP-341): Q = P + t*G where t = TaggedHash("TapTweak", P_x || merkle_root).
 *    If Q.y is odd, the effective secret scalar is negated mod n.
 *  - Nonce parity: Nonce point R must have even Y; if R.y is odd, nonces are negated mod n.
 *  - Verification equation: z * G = R + e * Q where e = TaggedHash("BIP0340/challenge", R_x || Q_x || m).
 */

import crypto from 'crypto';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import {
  FrostTaprootKeyShare,
  FrostTaprootNoncePair,
  FrostTaprootNonceCommitment,
  FrostTaprootSignatureShare,
  FrostTaprootSignature,
} from './types';

export const SECP256K1_ORDER: bigint = secp256k1.CURVE.n;
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

/**
 * Computes BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || ...data)
 */
export function taggedHash(tag: string, ...data: (Uint8Array | Buffer)[]): Buffer {
  const tagHash = crypto.createHash('sha256').update(tag).digest();
  const h = crypto.createHash('sha256').update(tagHash).update(tagHash);
  for (const d of data) {
    h.update(d);
  }
  return h.digest();
}

/**
 * Encodes a 32-byte BigInt as big-endian hex / Buffer.
 */
export function scalarToBytes32(scalar: bigint): Buffer {
  return Buffer.from(modN(scalar).toString(16).padStart(64, '0'), 'hex');
}

export function bytes32ToScalar(buf: Uint8Array | Buffer): bigint {
  return modN(BigInt('0x' + Buffer.from(buf).toString('hex')));
}

export function computeTaprootLagrangeCoefficient(i: number, participantIndices: number[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of participantIndices) {
    if (j === i) continue;
    num = modN(num * BigInt(j));
    den = modN(den * BigInt(j - i));
  }
  return modN(num * modInverseN(den));
}

/**
 * Computes Taproot tweak t = TaggedHash("TapTweak", P_x || merkleRoot)
 */
export function computeTaprootTweak(
  internalPubKeyX: Buffer,
  merkleRoot?: Buffer
): bigint {
  const data = merkleRoot ? [internalPubKeyX, merkleRoot] : [internalPubKeyX];
  const h = taggedHash('TapTweak', ...data);
  return bytes32ToScalar(h);
}

/**
 * Computes BIP-340 challenge scalar: e = TaggedHash("BIP0340/challenge", R_x || Q_x || msg) mod n
 */
export function computeBip340Challenge(
  R_x: Buffer,
  Q_x: Buffer,
  message: Uint8Array | Buffer
): bigint {
  const h = taggedHash('BIP0340/challenge', R_x, Q_x, message);
  return bytes32ToScalar(h);
}

/**
 * Computes FROST binding factor rho_i for Taproot signing.
 */
export function computeTaprootBindingFactor(
  participantIndex: number,
  message: Uint8Array | Buffer,
  commitments: FrostTaprootNonceCommitment[]
): bigint {
  const sorted = [...commitments].sort((a, b) => a.shareIndex - b.shareIndex);
  const data: (Uint8Array | Buffer)[] = [
    Buffer.from([participantIndex & 0xff]),
    message,
  ];
  for (const c of sorted) {
    data.push(Buffer.from(c.D_hex, 'hex'));
    data.push(Buffer.from(c.E_hex, 'hex'));
  }
  const h = taggedHash('FROST-BIP340/rho', ...data);
  return bytes32ToScalar(h);
}

/**
 * Autonomous Participant Round 1: Generate nonces d_i, e_i and commitments D_i, E_i.
 */
export function generateTaprootNoncePair(): FrostTaprootNoncePair {
  let d = 0n;
  let e = 0n;
  while (d === 0n) {
    d = modN(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  }
  while (e === 0n) {
    e = modN(BigInt('0x' + crypto.randomBytes(32).toString('hex')));
  }

  const D_pt = secp256k1.ProjectivePoint.BASE.multiply(d);
  const E_pt = secp256k1.ProjectivePoint.BASE.multiply(e);

  return {
    d,
    e,
    D_hex: Buffer.from(D_pt.toRawBytes(true)).toString('hex'),
    E_hex: Buffer.from(E_pt.toRawBytes(true)).toString('hex'),
  };
}

export interface TaprootKeyParityContext {
  internalKeyX: Buffer;
  outputKeyX: Buffer;
  tweak: bigint;
  negateInternalKey: boolean;
  negateOutputKey: boolean;
}

/**
 * Resolves the Taproot internal key P, output key Q = P + t*G, and even-Y parity flags.
 */
export function deriveTaprootKeysAndParity(
  internalPointHex: string,
  merkleRoot?: Buffer
): TaprootKeyParityContext {
  const clean = internalPointHex.startsWith('0x') ? internalPointHex.slice(2) : internalPointHex;
  let P: typeof secp256k1.ProjectivePoint.BASE;
  if (clean.length === 64) {
    // 32-byte x-only public key: lift with even-Y prefix 02
    P = secp256k1.ProjectivePoint.fromHex('02' + clean);
  } else {
    P = secp256k1.ProjectivePoint.fromHex(clean);
  }
  let P_aff = P.toAffine();

  let negateInternalKey = false;
  if (P_aff.y % 2n === 1n) {
    negateInternalKey = true;
    P = P.negate();
    P_aff = P.toAffine();
  }

  const internalKeyX = scalarToBytes32(P_aff.x);
  const tweak = computeTaprootTweak(internalKeyX, merkleRoot);

  let Q = P.add(secp256k1.ProjectivePoint.BASE.multiply(tweak));
  let Q_aff = Q.toAffine();

  let negateOutputKey = false;
  if (Q_aff.y % 2n === 1n) {
    negateOutputKey = true;
    Q = Q.negate();
    Q_aff = Q.toAffine();
  }

  const outputKeyX = scalarToBytes32(Q_aff.x);

  return {
    internalKeyX,
    outputKeyX,
    tweak,
    negateInternalKey,
    negateOutputKey,
  };
}

/**
 * Aggregates commitments into R = sum(D_i + rho_i * E_i) and checks R.y parity.
 */
export function aggregateTaprootGroupCommitment(
  commitments: FrostTaprootNonceCommitment[],
  message: Uint8Array | Buffer
): { R_x: Buffer; negateR: boolean; R_hex: string } {
  let R_total: typeof secp256k1.ProjectivePoint.BASE | null = null;

  for (const c of commitments) {
    const rho_i = computeTaprootBindingFactor(c.shareIndex, message, commitments);
    const D_pt = secp256k1.ProjectivePoint.fromHex(c.D_hex);
    const E_pt = secp256k1.ProjectivePoint.fromHex(c.E_hex);
    const R_i = D_pt.add(E_pt.multiply(rho_i));
    R_total = R_total ? R_total.add(R_i) : R_i;
  }

  if (!R_total) {
    throw new Error('[FROST-Taproot] No commitments provided for aggregation');
  }

  const R_aff = R_total.toAffine();
  const negateR = R_aff.y % 2n === 1n;
  const R_x = scalarToBytes32(R_aff.x);

  return {
    R_x,
    negateR,
    R_hex: R_x.toString('hex'),
  };
}

/**
 * Autonomous Participant Round 2: Compute partial signature share z_i.
 */
export function computeTaprootSignatureShare(
  keyShare: FrostTaprootKeyShare,
  noncePair: FrostTaprootNoncePair,
  commitments: FrostTaprootNonceCommitment[],
  domainParticipants: number[],
  parityCtx: TaprootKeyParityContext,
  R_x: Buffer,
  negateR: boolean,
  message: Uint8Array | Buffer
): FrostTaprootSignatureShare {
  const rho_i = computeTaprootBindingFactor(keyShare.shareIndex, message, commitments);
  const e_challenge = computeBip340Challenge(R_x, parityCtx.outputKeyX, message);
  const lambda_i = computeTaprootLagrangeCoefficient(keyShare.shareIndex, domainParticipants);

  let s_i = BigInt('0x' + keyShare.secretScalarHex) % N;
  if (parityCtx.negateInternalKey) {
    s_i = modN(N - s_i);
  }
  if (parityCtx.negateOutputKey) {
    s_i = modN(N - s_i);
  }

  let k_i = modN(noncePair.d + modN(rho_i * noncePair.e));
  if (negateR) {
    k_i = modN(N - k_i);
  }

  // z_i = k_i + (lambda_i * s_i * e) mod n
  const z_i = modN(k_i + modN(modN(lambda_i * s_i) * e_challenge));

  return {
    participantId: keyShare.participantId,
    shareIndex: keyShare.shareIndex,
    domain: keyShare.domain,
    zShareHex: scalarToBytes32(z_i).toString('hex'),
  };
}

/**
 * Aggregator: Combines partial shares and adds tweak to form a valid 64-byte BIP-340 signature.
 */
export function aggregateTaprootSignature(
  shares: FrostTaprootSignatureShare[],
  parityCtx: TaprootKeyParityContext,
  R_x: Buffer,
  message: Uint8Array | Buffer,
  network: 'mainnet' | 'testnet' = 'mainnet'
): FrostTaprootSignature {
  const e_challenge = computeBip340Challenge(R_x, parityCtx.outputKeyX, message);

  let z_sum = 0n;
  for (const s of shares) {
    const z_i = bytes32ToScalar(Buffer.from(s.zShareHex, 'hex'));
    z_sum = modN(z_sum + z_i);
  }

  // Coordinator adds tweak contribution: z = sum(z_i) + (tweak * e) mod n
  let effTweak = parityCtx.tweak;
  if (parityCtx.negateOutputKey) {
    effTweak = modN(N - effTweak);
  }
  const tweakTerm = modN(effTweak * e_challenge);
  const z = modN(z_sum + tweakTerm);

  const z_bytes = scalarToBytes32(z);
  const rawSig = Buffer.concat([R_x, z_bytes]);

  const isValid = schnorr.verify(rawSig, message, parityCtx.outputKeyX);
  if (!isValid) {
    throw new Error('[FROST-Taproot] Aggregated Schnorr signature failed BIP-340 cryptographic verification');
  }

  const taprootAddress = encodeBech32mTaprootAddress(parityCtx.outputKeyX, network);

  return {
    rawSignatureHex: rawSig.toString('hex'),
    R_x_hex: R_x.toString('hex'),
    z_hex: z_bytes.toString('hex'),
    outputKeyHex: parityCtx.outputKeyX.toString('hex'),
    internalKeyHex: parityCtx.internalKeyX.toString('hex'),
    taprootAddress,
  };
}

/**
 * BIP-350 Bech32m Address Encoder for Taproot (witness version 1).
 */
export function encodeBech32mTaprootAddress(
  program32Bytes: Buffer,
  network: 'mainnet' | 'testnet' = 'mainnet'
): string {
  const hrp = network === 'mainnet' ? 'bc' : 'tb';
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

  // Convert 8-bit bytes to 5-bit groups
  const data5Bit: number[] = [1]; // Witness version 1
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < program32Bytes.length; i++) {
    acc = (acc << 8) | program32Bytes[i];
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      data5Bit.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) {
    data5Bit.push((acc << (5 - bits)) & 31);
  }

  // Bech32m checksum calculation (constant: 0x2bc830a3)
  function polymod(values: number[]): number {
    const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const val of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ val;
      for (let i = 0; i < 5; i++) {
        if ((top >> i) & 1) {
          chk ^= GENERATOR[i];
        }
      }
    }
    return chk;
  }

  function hrpExpand(hrpStr: string): number[] {
    const ret: number[] = [];
    for (let i = 0; i < hrpStr.length; i++) ret.push(hrpStr.charCodeAt(i) >> 5);
    ret.push(0);
    for (let i = 0; i < hrpStr.length; i++) ret.push(hrpStr.charCodeAt(i) & 31);
    return ret;
  }

  const values = hrpExpand(hrp).concat(data5Bit).concat([0, 0, 0, 0, 0, 0]);
  const mod = polymod(values) ^ 0x2bc830a3; // Bech32m constant
  const checksum: number[] = [];
  for (let p = 0; p < 6; p++) {
    checksum.push((mod >> (5 * (5 - p))) & 31);
  }

  const combined = data5Bit.concat(checksum);
  let res = hrp + '1';
  for (const c of combined) {
    res += CHARSET[c];
  }
  return res;
}

/**
 * Verifies an individual participant's Taproot FROST signature share (identifiable abort).
 * Checks: z_i * G == R_i + (e * lambda_i) * P_i
 */
export function verifyTaprootSignatureShare(
  share: FrostTaprootSignatureShare,
  commitment: FrostTaprootNonceCommitment,
  allCommitments: FrostTaprootNonceCommitment[],
  domainParticipants: number[],
  participantPublicKeyHex: string,
  parityCtx: TaprootKeyParityContext,
  R_x: Buffer,
  negateR: boolean,
  message: Uint8Array | Buffer
): { valid: boolean; reason?: string } {
  try {
    const rho_i = computeTaprootBindingFactor(share.shareIndex, message, allCommitments);
    const e_challenge = computeBip340Challenge(R_x, parityCtx.outputKeyX, message);
    const lambda_i = computeTaprootLagrangeCoefficient(share.shareIndex, domainParticipants);

    const z_i = bytes32ToScalar(Buffer.from(share.zShareHex, 'hex'));
    const D_pt = secp256k1.ProjectivePoint.fromHex(commitment.D_hex);
    const E_pt = secp256k1.ProjectivePoint.fromHex(commitment.E_hex);

    let P_i = secp256k1.ProjectivePoint.fromHex(participantPublicKeyHex);
    if (parityCtx.negateInternalKey) {
      P_i = P_i.negate();
    }
    if (parityCtx.negateOutputKey) {
      P_i = P_i.negate();
    }

    // Left: z_i * G
    const left = secp256k1.ProjectivePoint.BASE.multiply(z_i);

    // Right: R_i + (e * lambda_i) * P_i
    let R_i = D_pt.add(E_pt.multiply(rho_i));
    if (negateR) {
      R_i = R_i.negate();
    }
    const coeff = modN(e_challenge * lambda_i);
    const right = R_i.add(P_i.multiply(coeff));

    if (!left.equals(right)) {
      return {
        valid: false,
        reason: `Participant ${share.participantId} submitted invalid Taproot signature share`,
      };
    }
    return { valid: true };
  } catch (err: any) {
    return { valid: false, reason: err.message || 'Taproot share verification failed' };
  }
}

export interface TaprootDkgResult {
  internalPublicKeyHex: string; // 33-byte compressed P
  internalKeyXHex: string;      // 32-byte x-only P_aff.x
  outputPublicKeyHex: string;   // 32-byte x-only Q_aff.x
  taprootAddress: string;
  parityContext: TaprootKeyParityContext;
  participantShares: Map<number, FrostTaprootKeyShare>;
  commitments: Map<number, string[]>;
}

/**
 * Executes a pure dealerless DKG ceremony over secp256k1 for Bitcoin Taproot.
 * Computes internal key P, validates even-Y parity, applies Taproot tweak t,
 * and generates output key Q and Bech32m address without central key reconstruction.
 */
export function executeTaprootDealerlessDkg(
  participants: { id: string; index: number; domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE' }[],
  threshold: number,
  merkleRoot?: Buffer,
  network: 'mainnet' | 'testnet' = 'testnet'
): TaprootDkgResult {
  const n = participants.length;
  if (threshold < 1 || threshold > n) {
    throw new Error(`[FROST-Taproot DKG] Invalid threshold ${threshold} for ${n} participants`);
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

      // Verify share
      const lhs = secp256k1.ProjectivePoint.BASE.multiply(s_ij);
      let rhs: typeof secp256k1.ProjectivePoint.BASE | null = null;
      let x_pow = 1n;
      for (let k = 0; k < threshold; k++) {
        const C_k = secp256k1.ProjectivePoint.fromHex(comms[k]);
        const term = C_k.multiply(x_pow);
        rhs = rhs ? rhs.add(term) : term;
        x_pow = modN(x_pow * x);
      }

      if (!lhs.equals(rhs!)) {
        throw new Error(
          `[FROST-Taproot DKG] Share verification failed from ${dealer.id} to ${recipient.id}`
        );
      }

      sharesFor.get(recipient.index)!.push(s_ij);
    }
  }

  // 3. Aggregate internal public key P = sum_{i=1}^n C_i0
  let P_point: typeof secp256k1.ProjectivePoint.BASE | null = null;
  for (const p of participants) {
    const c0_hex = feldmanCommitments.get(p.index)![0];
    const C0 = secp256k1.ProjectivePoint.fromHex(c0_hex);
    P_point = P_point ? P_point.add(C0) : C0;
  }

  const P_hex = Buffer.from(P_point!.toRawBytes(true)).toString('hex');
  const parityContext = deriveTaprootKeysAndParity(P_hex, merkleRoot);
  const taprootAddress = encodeBech32mTaprootAddress(parityContext.outputKeyX, network);

  const participantShares = new Map<number, FrostTaprootKeyShare>();

  for (const p of participants) {
    const received = sharesFor.get(p.index)!;
    let s_j = 0n;
    for (const sh of received) {
      s_j = modN(s_j + sh);
    }

    const P_j = secp256k1.ProjectivePoint.BASE.multiply(s_j);

    participantShares.set(p.index, {
      participantId: p.id,
      shareIndex: p.index,
      domain: p.domain,
      secretScalarHex: scalarToBytes32(s_j).toString('hex'),
      publicKeyHex: Buffer.from(P_j.toRawBytes(true)).toString('hex'),
      groupPublicKeyHex: parityContext.outputKeyX.toString('hex'),
    });
  }

  return {
    internalPublicKeyHex: P_hex,
    internalKeyXHex: parityContext.internalKeyX.toString('hex'),
    outputPublicKeyHex: parityContext.outputKeyX.toString('hex'),
    taprootAddress,
    parityContext,
    participantShares,
    commitments: feldmanCommitments,
  };
}
