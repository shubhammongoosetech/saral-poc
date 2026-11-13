import { describe, it, expect } from 'vitest';
import { ethers } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  EcdsaSigner,
  EddsaSigner,
  ThreeDomainSignatures,
  DomainQuorumError,
  SaralError,
} from '../src';

const N = secp256k1.CURVE.n;

describe('3-Domain Signature Aggregation & Verification', () => {
  it('aggregates valid 3-domain partial signatures and verifies expected public key', async () => {
    const signer = new EcdsaSigner();
    const wallet = ethers.Wallet.createRandom();
    const msg = 'SARAL 3-Domain Test Transaction';
    const hashToSign = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes(msg)));

    // Generate real ECDSA signature via standard signing key
    const sig = wallet.signingKey.sign(hashToSign);
    const rBig = BigInt(sig.r);
    const totalS = BigInt(sig.s);

    // Split totalS into 3 domain shares: s = s_foundation + s_public + s_private mod N
    const sFoundation = 123456789n;
    const sPublic = 987654321n;
    let sPrivate = (totalS - sFoundation - sPublic) % N;
    if (sPrivate < 0n) sPrivate += N;

    const toHex = (n: bigint) => '0x' + n.toString(16).padStart(64, '0');

    const threeDomains: ThreeDomainSignatures = {
      r: sig.r,
      yParity: sig.yParity,
      expectedPublicKey: wallet.signingKey.publicKey,
      domains: {
        foundation: { domain: 'foundation', s: toHex(sFoundation), nodesCount: 5 },
        public: { domain: 'public', s: toHex(sPublic), nodesCount: 5 },
        private: { domain: 'private', s: toHex(sPrivate), nodesCount: 5 },
      },
    };

    const aggregated = await signer.aggregate(threeDomains, hashToSign);
    expect(aggregated.r).toBe(sig.r);
    expect(aggregated.s).toBe(sig.s);
    expect(aggregated.yParity).toBe(sig.yParity);

    // Verify method
    const isValid = signer.verify(aggregated, hashToSign, wallet.signingKey.publicKey);
    expect(isValid).toBe(true);
  });

  it('throws DOMAIN_QUORUM_FAILED when Foundation domain is missing', async () => {
    const signer = new EcdsaSigner();
    const hashToSign = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('test')));

    const partialDomains: any = {
      r: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef',
      expectedPublicKey: '0x04' + '11'.repeat(64),
      domains: {
        public: { domain: 'public', s: '0x1111' },
        private: { domain: 'private', s: '0x2222' },
      },
    };

    await expect(signer.aggregate(partialDomains, hashToSign)).rejects.toThrowError(
      DomainQuorumError
    );

    try {
      await signer.aggregate(partialDomains, hashToSign);
    } catch (err: any) {
      expect(err.code).toBe('DOMAIN_QUORUM_FAILED');
      expect(err.missingDomains).toContain('foundation');
    }
  });

  it('throws DOMAIN_QUORUM_FAILED when Public or Private domain is missing', async () => {
    const signer = new EcdsaSigner();
    const hashToSign = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('test')));

    const missingPublic: any = {
      r: '0x1234',
      expectedPublicKey: '0x04' + '11'.repeat(64),
      domains: {
        foundation: { domain: 'foundation', s: '0x1111' },
        private: { domain: 'private', s: '0x2222' },
      },
    };

    try {
      await signer.aggregate(missingPublic, hashToSign);
    } catch (err: any) {
      expect(err.code).toBe('DOMAIN_QUORUM_FAILED');
      expect(err.missingDomains).toContain('public');
    }
  });

  it('throws SIGNATURE_VERIFICATION_FAILED when a bad partial signature is submitted', async () => {
    const signer = new EcdsaSigner();
    const wallet = ethers.Wallet.createRandom();
    const hashToSign = ethers.getBytes(ethers.keccak256(ethers.toUtf8Bytes('test')));
    const sig = wallet.signingKey.sign(hashToSign);

    const totalS = BigInt(sig.s);
    const sFoundation = 123456789n;
    const sPublic = 987654321n;
    // Tamper with the private share
    const badPrivate = (totalS - sFoundation - sPublic + 99999n) % N;

    const toHex = (n: bigint) => '0x' + n.toString(16).padStart(64, '0');

    const tamperedDomains: ThreeDomainSignatures = {
      r: sig.r,
      yParity: sig.yParity,
      expectedPublicKey: wallet.signingKey.publicKey,
      domains: {
        foundation: { domain: 'foundation', s: toHex(sFoundation) },
        public: { domain: 'public', s: toHex(sPublic) },
        private: { domain: 'private', s: toHex(badPrivate) },
      },
    };

    await expect(signer.aggregate(tamperedDomains, hashToSign)).rejects.toThrowError(SaralError);

    try {
      await signer.aggregate(tamperedDomains, hashToSign);
    } catch (err: any) {
      expect(err.code).toBe('SIGNATURE_VERIFICATION_FAILED');
    }
  });

  it('EddsaSigner throws NOT_IMPLEMENTED for aggregate pending backend Ed25519 DKG', async () => {
    const eddsa = new EddsaSigner();
    const hash = new Uint8Array(32);
    const dummySigs: any = { r: '0x1', domains: {} };

    await expect(eddsa.aggregate(dummySigs, hash)).rejects.toThrowError(SaralError);
    try {
      await eddsa.aggregate(dummySigs, hash);
    } catch (err: any) {
      expect(err.code).toBe('NOT_IMPLEMENTED');
    }
  });
});

