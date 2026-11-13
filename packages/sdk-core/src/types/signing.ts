import { CurveType, SignatureScheme } from './chain';
import { SignatureResult } from './adapter';

export type DomainName = 'foundation' | 'public' | 'private';

export interface DomainPartialSignature {
  /** The SARAL security domain */
  domain: DomainName;
  /** Partial signature scalar s_domain in hex format */
  s: string;
  /** Number of participant nodes that satisfied threshold in this domain */
  nodesCount?: number;
  /** Authenticated coordinator / domain signature proof */
  signature?: string;
}

export interface ThreeDomainSignatures {
  /** Ephemeral shared curve point R / r scalar (hex) */
  r: string;
  /** Parity bit for public key recovery (0 or 1) */
  yParity?: number;
  /** The expected derived aggregated public key of the wallet (hex) */
  expectedPublicKey: string;
  /** Contributions from all 3 domains — ALL 3 REQUIRED */
  domains: {
    foundation: DomainPartialSignature;
    public: DomainPartialSignature;
    private: DomainPartialSignature;
  };
}

export interface SignerBackend {
  readonly curve: CurveType;
  readonly scheme: SignatureScheme;

  /**
   * Aggregates verified partial signatures from Foundation, Public, and Private domains.
   * Throws DOMAIN_QUORUM_FAILED if any domain is missing.
   * Throws SIGNATURE_VERIFICATION_FAILED if recovered key fails to match expectedPublicKey.
   */
  aggregate(
    signatures: ThreeDomainSignatures,
    hashToSign: Uint8Array
  ): Promise<SignatureResult>;

  /**
   * Verifies the aggregated signature against the public key and message hash.
   */
  verify(
    signature: SignatureResult,
    hashToSign: Uint8Array,
    expectedPublicKey: string | Uint8Array
  ): boolean;
}

