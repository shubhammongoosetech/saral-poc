import { ethers } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';
import { CurveType, SignatureScheme } from '../types/chain';
import { ThreeDomainSignatures, SignerBackend } from '../types/signing';
import { SignatureResult } from '../types/adapter';
import { DomainQuorumError, SaralError } from '../errors/SaralError';

const N = secp256k1.CURVE.n;
const HALF_N = N / 2n;

function toHex32(n: bigint): string {
  return '0x' + n.toString(16).padStart(64, '0');
}

function parseScalar(val: string, name: string): bigint {
  const clean = val.trim();
  const hex = clean.startsWith('0x') ? clean : '0x' + clean;
  try {
    const b = BigInt(hex);
    if (b < 0n || b >= N) {
      throw new Error('Scalar out of range');
    }
    return b;
  } catch {
    throw new SaralError('INVALID_CONFIG', `Invalid ${name} scalar: ${val}`);
  }
}

export class EcdsaSigner implements SignerBackend {
  public readonly curve: CurveType = 'secp256k1';
  public readonly scheme: SignatureScheme = 'ecdsa';

  /**
   * Aggregates verified partial signature scalars from all 3 domains:
   * Foundation, Public, and Private.
   *
   * Invariants enforced:
   *   1. 3-of-3 domains must be present and non-empty.
   *   2. s = (s_foundation + s_public + s_private) mod N.
   *   3. Enforces canonical low-s (BIP-62 / EIP-2).
   *   4. Recovers public key from (r, s, yParity) and compares against expectedPublicKey.
   */
  public async aggregate(
    signatures: ThreeDomainSignatures,
    hashToSign: Uint8Array
  ): Promise<SignatureResult> {
    // 1. Verify 3-of-3 Domain Quorum
    const missing: string[] = [];
    if (!signatures.domains?.foundation?.s || signatures.domains.foundation.s.trim() === '') {
      missing.push('foundation');
    }
    if (!signatures.domains?.public?.s || signatures.domains.public.s.trim() === '') {
      missing.push('public');
    }
    if (!signatures.domains?.private?.s || signatures.domains.private.s.trim() === '') {
      missing.push('private');
    }

    if (missing.length > 0) {
      throw new DomainQuorumError(missing);
    }

    // 2. Parse Scalars
    const r = parseScalar(signatures.r, 'r');
    if (r === 0n) {
      throw new SaralError('DOMAIN_QUORUM_FAILED', 'Signature scalar r must not be zero.');
    }

    const sF = parseScalar(signatures.domains.foundation.s, 'foundation s');
    const sP = parseScalar(signatures.domains.public.s, 'public s');
    const sU = parseScalar(signatures.domains.private.s, 'private s');

    // 3. Modulo Addition across the 3 domains
    let aggregatedS = (sF + sP + sU) % N;
    if (aggregatedS < 0n) {
      aggregatedS = (aggregatedS + N) % N;
    }
    if (aggregatedS === 0n) {
      throw new SaralError('DOMAIN_QUORUM_FAILED', 'Aggregated signature scalar s evaluated to zero mod N.');
    }

    // 4. Canonical Low-S
    let yParity: 0 | 1 = signatures.yParity === 1 ? 1 : 0;
    let finalS = aggregatedS;
    if (finalS > HALF_N) {
      finalS = N - finalS;
      yParity = yParity === 1 ? 0 : 1;
    }

    const rHex = toHex32(r);
    const sHex = toHex32(finalS);
    const msgHashHex = ethers.hexlify(hashToSign);

    // 5. Verify against expected public key
    const expectedPk = signatures.expectedPublicKey.trim();
    let expectedAddress: string;
    try {
      const cleanPk = expectedPk.startsWith('0x') ? expectedPk : '0x' + expectedPk;
      expectedAddress = cleanPk.length === 42 ? ethers.getAddress(cleanPk) : ethers.computeAddress(cleanPk);
    } catch {
      throw new SaralError('INVALID_CONFIG', `Invalid expectedPublicKey format: ${expectedPk}`);
    }

    // Test the candidate parity
    let validParity: 0 | 1 | null = null;
    const paritiesToTry: (0 | 1)[] = signatures.yParity !== undefined ? [yParity, yParity === 0 ? 1 : 0] : [0, 1];

    for (const p of paritiesToTry) {
      try {
        const sig = ethers.Signature.from({ r: rHex, s: sHex, yParity: p });
        const recoveredAddr = ethers.recoverAddress(msgHashHex, sig);
        if (recoveredAddr.toLowerCase() === expectedAddress.toLowerCase()) {
          validParity = p;
          break;
        }
      } catch {
        // Continue trial
      }
    }

    if (validParity === null) {
      throw new SaralError(
        'SIGNATURE_VERIFICATION_FAILED',
        `Aggregated 3-domain signature does not match expected public key / address '${expectedAddress}'.`,
        { expectedAddress, r: rHex, s: sHex }
      );
    }

    const rBytes = ethers.getBytes(rHex);
    const sBytes = ethers.getBytes(sHex);
    const rawBytes = new Uint8Array(65);
    rawBytes.set(rBytes, 0);
    rawBytes.set(sBytes, 32);
    rawBytes[64] = validParity;

    return {
      r: rHex,
      s: sHex,
      yParity: validParity,
      v: validParity + 27,
      rawBytes,
    };
  }

  /**
   * Verifies an ECDSA signature against the message hash and public key.
   */
  public verify(
    signature: SignatureResult,
    hashToSign: Uint8Array,
    expectedPublicKey: string | Uint8Array
  ): boolean {
    try {
      const msgHashHex = ethers.hexlify(hashToSign);
      const yParity: 0 | 1 = signature.yParity === 1 ? 1 : 0;
      const sig = ethers.Signature.from({
        r: signature.r,
        s: signature.s,
        yParity,
      });

      const pkHex =
        typeof expectedPublicKey === 'string'
          ? expectedPublicKey.startsWith('0x')
            ? expectedPublicKey
            : '0x' + expectedPublicKey
          : ethers.hexlify(expectedPublicKey);

      const expectedAddress = pkHex.length === 42 ? ethers.getAddress(pkHex) : ethers.computeAddress(pkHex);
      const recovered = ethers.recoverAddress(msgHashHex, sig);
      return recovered.toLowerCase() === expectedAddress.toLowerCase();
    } catch {
      return false;
    }
  }
}
