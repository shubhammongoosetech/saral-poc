import { ed25519 } from '@noble/curves/ed25519';
import { CurveType, SignatureScheme } from '../types/chain';
import { ThreeDomainSignatures, SignerBackend } from '../types/signing';
import { SignatureResult } from '../types/adapter';
import { SaralError } from '../errors/SaralError';

export class EddsaSigner implements SignerBackend {
  public readonly curve: CurveType = 'ed25519';
  public readonly scheme: SignatureScheme = 'eddsa';

  /**
   * Aggregates 3-Domain FROST-Ed25519 / RFC 9591 partial signatures into standard 64-byte EdDSA signature.
   *
   * Marked NOT_IMPLEMENTED on client until backend Ed25519 threshold DKG deployment is live.
   */
  public async aggregate(
    _signatures: ThreeDomainSignatures,
    _hashToSign: Uint8Array
  ): Promise<SignatureResult> {
    throw new SaralError(
      'NOT_IMPLEMENTED',
      'EdDSA (FROST-Ed25519) 3-domain threshold aggregation is not yet implemented on the backend. Scheduled for upcoming release.',
      { curve: this.curve, scheme: this.scheme }
    );
  }

  /**
   * Verifies standard 64-byte Ed25519 signature against 32-byte public key and message.
   */
  public verify(
    signature: SignatureResult,
    hashToSign: Uint8Array,
    expectedPublicKey: string | Uint8Array
  ): boolean {
    try {
      const pubkeyBytes =
        typeof expectedPublicKey === 'string'
          ? Buffer.from(
              expectedPublicKey.startsWith('0x') ? expectedPublicKey.slice(2) : expectedPublicKey,
              'hex'
            )
          : expectedPublicKey;

      return ed25519.verify(signature.rawBytes, hashToSign, pubkeyBytes);
    } catch {
      return false;
    }
  }
}

