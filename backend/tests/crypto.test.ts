/**
 * crypto.test.ts
 *
 * Comprehensive Cryptographic & DKG Test Suite for SARAL.
 * Validates:
 *   1. secp256k1 Field Math & Randomness
 *   2. Feldman VSS commitments and homomorphic verification
 *   3. Distributed Key Generation (DKG) without a trusted dealer (Patent Claims 1, 11)
 *   4. Homomorphic point aggregation: Q = Q_F + Q_P + Q_V
 *   5. EVM address derivation directly from public curve point
 *   6. Threshold ECDSA 3-of-3 AND cross-domain signing (Patent [0014]-[0017])
 *   7. Signature verification with ethers.recoverAddress === wallet.address
 */

import test from 'node:test';
import assert from 'node:assert';
import { ethers } from 'ethers';
import { secp256k1 } from '@noble/curves/secp256k1';

import {
  CURVE_ORDER,
  modN,
  modInverse,
  randomScalar,
  scalarMultiplyG,
  scalarToHex,
  hexToScalar,
  G,
} from '../src/crypto/secp256k1Math';
import {
  splitSecretField,
  reconstructSecretField,
  verifyShareWithCommitments,
  computeLagrangeCoefficient,
  generateZeroPolynomial,
  evaluateZeroPolynomial,
} from '../src/crypto/shamirField';
import {
  dkgPhase1_generateContribution,
  dkgPhase1_computeSubShares,
  dkgPhase2_verifySubShare,
  dkgPhase3_accumulateShares,
  dkgComputeDomainPublicKey,
  runDomainDkgSimulation,
  runFullSaralDkg,
} from '../src/crypto/dkg';
import {
  generateSaralWalletMpc,
  aggregateDomainPublicKeys,
  computeEffectiveAdditiveShares,
  executeMpcThresholdSign,
} from '../src/crypto/thresholdEcdsa';

test('1. Field Math: secp256k1 F_n scalars & operations', () => {
  const s1 = randomScalar();
  const s2 = randomScalar();
  assert.notStrictEqual(s1, s2, 'Random scalars must be distinct');
  assert.ok(s1 > 0n && s1 < CURVE_ORDER, 's1 must be in [1, n-1]');
  assert.ok(s2 > 0n && s2 < CURVE_ORDER, 's2 must be in [1, n-1]');

  const inv1 = modInverse(s1, CURVE_ORDER);
  const prod = modN(s1 * inv1);
  assert.strictEqual(prod, 1n, 'Scalar multiplied by modular inverse must equal 1 mod n');

  const hex = scalarToHex(s1);
  assert.strictEqual(hex.length, 64, 'Hex scalar representation must be 64 characters');
  assert.strictEqual(hexToScalar(hex), s1, 'hexToScalar must invert scalarToHex exactly');
});

test('2. Elliptic Curve Arithmetic: Point addition & scalar multiplication', () => {
  const k1 = randomScalar();
  const k2 = randomScalar();

  const P1 = scalarMultiplyG(k1);
  const P2 = scalarMultiplyG(k2);

  // Homomorphic property: (k1 + k2) * G == k1*G + k2*G
  const kSum = modN(k1 + k2);
  const PExpected = scalarMultiplyG(kSum);
  const PActual = P1.add(P2);

  assert.strictEqual(
    PActual.toHex(true),
    PExpected.toHex(true),
    'Point addition must be homomorphic to scalar addition'
  );
});

test('3. Feldman VSS: Commitments verify shares without revealing secret', () => {
  const secret = randomScalar();
  const total = 6;
  const threshold = 4;

  const sharing = splitSecretField(secret, total, threshold);
  assert.strictEqual(sharing.shares.length, total);
  assert.strictEqual(sharing.commitments.length, threshold);

  // Each legitimate share must pass commitment verification
  for (const share of sharing.shares) {
    const valid = verifyShareWithCommitments(share, sharing.commitments);
    assert.ok(valid, `Share at index ${share.index} must verify against Feldman commitments`);
  }

  // Tampered share must fail verification
  const tamperedShare = { index: sharing.shares[0].index, value: modN(sharing.shares[0].value + 1n) };
  const tamperedValid = verifyShareWithCommitments(tamperedShare, sharing.commitments);
  assert.strictEqual(tamperedValid, false, 'Tampered share must fail Feldman verification');
});

test('4. DKG Protocol (Patent Claim 1, 11): No dealer, joint polynomial sampling', () => {
  const nodeIds = ['saral-public-1', 'saral-public-2', 'saral-public-3', 'saral-public-4', 'saral-public-5', 'saral-public-6'];
  const threshold = 4;
  const totalNodes = 6;

  // Execute DKG simulation across the 6 nodes
  const dkg = runDomainDkgSimulation('PUBLIC', nodeIds, threshold);

  assert.strictEqual(dkg.domain, 'PUBLIC');
  assert.strictEqual(dkg.nodeShares.size, totalNodes);
  assert.strictEqual(dkg.allCommitments.size, totalNodes);
  assert.ok(dkg.domainPublicKeyHex.length > 0, 'Domain public key must be computed');

  // Verify that each node's share is non-zero
  for (const [nodeId, share] of dkg.nodeShares) {
    assert.ok(share > 0n && share < CURVE_ORDER, `Node ${nodeId} share must be valid non-zero scalar`);
  }

  // Verify that any quorum of `threshold` shares reconstructs to the domain public key IN THE EXPONENT
  // Sum_{i in Quorum} lambda_i * S_i * G == Q_d
  const quorumIndices = [1, 2, 4, 6];
  let reconstructedPoint: typeof G | null = null;

  for (const idx of quorumIndices) {
    const nodeId = nodeIds[idx - 1];
    const shareVal = dkg.nodeShares.get(nodeId)!;
    const lambda = computeLagrangeCoefficient(idx, quorumIndices);
    const effectiveShare = modN(lambda * shareVal);
    const pt = scalarMultiplyG(effectiveShare);
    reconstructedPoint = reconstructedPoint ? reconstructedPoint.add(pt) : pt;
  }

  assert.ok(reconstructedPoint !== null);
  assert.strictEqual(
    reconstructedPoint!.toHex(true),
    dkg.domainPublicKeyHex,
    'Lagrange-weighted DKG shares in exponent must reconstruct exactly to the domain public key'
  );
});

test('5. 3-Domain Homomorphic Aggregation: Q = Q_F + Q_P + Q_V and address derivation', () => {
  const fN = 7; const fT = 5;
  const pN = 6; const pT = 5;
  const vN = 6; const vT = 5;

  const foundationIds = Array.from({ length: fN }, (_, i) => `saral-foundation-${i + 1}`);
  const publicIds = Array.from({ length: pN }, (_, i) => `saral-public-${i + 1}`);
  const privateIds = Array.from({ length: vN }, (_, i) => `saral-private-${i + 1}`);

  const fullDkg = runFullSaralDkg(foundationIds, publicIds, privateIds, {
    foundation: fT,
    public: pT,
    private: vT,
  });

  assert.ok(fullDkg.aggregatePublicKeyHex.length > 0);

  // Address derived directly from aggregate public key
  const cleanHex = fullDkg.aggregatePublicKeyHex.startsWith('0x')
    ? fullDkg.aggregatePublicKeyHex
    : '0x' + fullDkg.aggregatePublicKeyHex;
  const address = ethers.computeAddress(cleanHex);
  assert.ok(ethers.isAddress(address), 'Address must be a valid checksummed Ethereum address');

  // Verify point addition property: Q = Q_F + Q_P + Q_V
  const ptF = secp256k1.ProjectivePoint.fromHex(fullDkg.foundationDkg.domainPublicKeyHex.replace(/^0x/, ''));
  const ptP = secp256k1.ProjectivePoint.fromHex(fullDkg.publicDkg.domainPublicKeyHex.replace(/^0x/, ''));
  const ptV = secp256k1.ProjectivePoint.fromHex(fullDkg.privateDkg.domainPublicKeyHex.replace(/^0x/, ''));
  const ptExpected = ptF.add(ptP).add(ptV);

  assert.strictEqual(
    cleanHex.toLowerCase(),
    ('0x' + ptExpected.toHex(true)).toLowerCase(),
    'Aggregated public key must equal Q_F + Q_P + Q_V'
  );
});

test('6. generateSaralWalletMpc integration: Distributed generation across 19 nodes', () => {
  // 19 nodes: Foundation 7, Public 6, Private 6 (D-05)
  const wallet = generateSaralWalletMpc(6, 5, 7, 5, 6, 5);

  assert.ok(ethers.isAddress(wallet.address), 'Wallet address must be valid');
  assert.strictEqual(wallet.foundation.totalShares, 7);
  assert.strictEqual(wallet.foundation.threshold, 5);
  assert.strictEqual(wallet.publicDomain.totalShares, 6);
  assert.strictEqual(wallet.publicDomain.threshold, 5);
  assert.strictEqual(wallet.privateDomain.totalShares, 6);
  assert.strictEqual(wallet.privateDomain.threshold, 5);

  // Verify all shares satisfy their respective domain commitments
  for (const s of wallet.foundation.shares) {
    assert.ok(verifyShareWithCommitments(s, wallet.foundation.commitments));
  }
  for (const s of wallet.publicDomain.shares) {
    assert.ok(verifyShareWithCommitments(s, wallet.publicDomain.commitments));
  }
  for (const s of wallet.privateDomain.shares) {
    assert.ok(verifyShareWithCommitments(s, wallet.privateDomain.commitments));
  }
});

test('7. Threshold ECDSA (Patent [0014]-[0017]): 3-of-3 AND cross-domain signing', async () => {
  // Setup 19-node wallet via DKG
  const wallet = generateSaralWalletMpc(6, 5, 7, 5, 6, 5);

  // Construct unsigned transaction
  const unsignedTx = ethers.Transaction.from({
    to: '0x1111111111111111111111111111111111111111',
    value: ethers.parseEther('0.05'),
    nonce: 0,
    gasPrice: 1000000000n,
    gasLimit: 21000n,
    chainId: 91562037n,
    type: 0,
  });

  // Select valid quorums: Foundation (5 of 7), Public (5 of 6), Private (5 of 6)
  const foundQuorum = wallet.foundation.shares.slice(0, 5);
  const pubQuorum = wallet.publicDomain.shares.slice(0, 5);
  const privQuorum = wallet.privateDomain.shares.slice(0, 5);

  const sigResult = await executeMpcThresholdSign({
    unsignedTxSerialized: unsignedTx.unsignedSerialized,
    chainId: 91562037n,
    foundation: {
      domain: 'FOUNDATION',
      activeShareIndices: foundQuorum.map((s) => s.index),
      shareValues: foundQuorum.map((s) => s.value),
    },
    publicDomain: {
      domain: 'PUBLIC',
      activeShareIndices: pubQuorum.map((s) => s.index),
      shareValues: pubQuorum.map((s) => s.value),
    },
    privateDomain: {
      domain: 'PRIVATE',
      activeShareIndices: privQuorum.map((s) => s.index),
      shareValues: privQuorum.map((s) => s.value),
    },
  });

  assert.ok(sigResult.r.startsWith('0x'));
  assert.ok(sigResult.s.startsWith('0x'));
  assert.ok(sigResult.rawSignedTx.startsWith('0x'));
  assert.ok(sigResult.txHash.startsWith('0x'));

  // Signature verification: recover address using ethers
  const msgHash = ethers.keccak256(unsignedTx.unsignedSerialized);
  const recoveredSigner = ethers.recoverAddress(msgHash, {
    r: sigResult.r,
    s: sigResult.s,
    yParity: sigResult.yParity,
  });

  assert.strictEqual(
    recoveredSigner.toLowerCase(),
    wallet.address.toLowerCase(),
    'Recovered signer from threshold ECDSA signature must equal the wallet address exactly'
  );
});

test('8. Separation of Powers Failure Mode: <3 domains must always fail', async () => {
  const wallet = generateSaralWalletMpc(6, 5, 7, 5, 6, 5);
  const unsignedTx = ethers.Transaction.from({
    to: '0x1111111111111111111111111111111111111111',
    value: ethers.parseEther('0.01'),
    nonce: 0,
    gasPrice: 1000000000n,
    gasLimit: 21000n,
    chainId: 91562037n,
  });

  // Attempt signing with Public and Private alone (Foundation missing)
  const pubQuorum = wallet.publicDomain.shares.slice(0, 5);
  const privQuorum = wallet.privateDomain.shares.slice(0, 5);

  await assert.rejects(
    async () => {
      await executeMpcThresholdSign({
        unsignedTxSerialized: unsignedTx.unsignedSerialized,
        chainId: 91562037n,
        foundation: {
          domain: 'FOUNDATION',
          activeShareIndices: [],
          shareValues: [],
        },
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: pubQuorum.map((s) => s.index),
          shareValues: pubQuorum.map((s) => s.value),
        },
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: privQuorum.map((s) => s.index),
          shareValues: privQuorum.map((s) => s.value),
        },
      });
    },
    /Separation of Powers/i,
    'Signing without Foundation domain must be rejected by Separation of Powers'
  );

  // Attempt signing with fewer than threshold nodes in Public domain (e.g. 3 of 5 required)
  await assert.rejects(
    async () => {
      await executeMpcThresholdSign({
        unsignedTxSerialized: unsignedTx.unsignedSerialized,
        chainId: 91562037n,
        foundation: {
          domain: 'FOUNDATION',
          activeShareIndices: wallet.foundation.shares.slice(0, 5).map((s) => s.index),
          shareValues: wallet.foundation.shares.slice(0, 5).map((s) => s.value),
        },
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: wallet.publicDomain.shares.slice(0, 3).map((s) => s.index),
          shareValues: wallet.publicDomain.shares.slice(0, 3).map((s) => s.value),
        },
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: privQuorum.map((s) => s.index),
          shareValues: privQuorum.map((s) => s.value),
        },
      });
    },
    /Public domain quorum shortfall/i,
    'Signing with insufficient Public nodes must be rejected'
  );
});

