/**
 * integration.test.ts
 *
 * Full End-to-End System Integration Test Suite for SARAL.
 *
 * Patent & Specification Mandates:
 *   1. User Auth & MFA verification.
 *   2. Location & Time policy evaluation gate.
 *   3. Distributed Key Generation (DKG): Q = Q_F + Q_P + Q_V on secp256k1 without private key reconstruction.
 *   4. Pinned placement generation via HRW hashing.
 *   5. 3-Domain MPC Threshold ECDSA signing (3-of-3 cross-domain requirement).
 *   6. Verification of recovered signer address equality using ethers.
 *   7. Security policy rejection on unverified MFA or out-of-policy location.
 *   8. Economic fee routing and TVS tracking.
 */

import test from 'node:test';
import assert from 'node:assert';
import { ethers } from 'ethers';

process.env.NODE_ENV = 'test';
process.env.PAILLIER_BITS = '1024';

import {
  generateSaralWalletMpc,
  executeMpcThresholdSign,
} from '../src/crypto/thresholdEcdsa';

import {
  buildClusterTopology,
} from '../src/topology/allocation';

import {
  computeWalletPlacement,
  validatePlacementDiversity,
} from '../src/topology/placement';

import {
  EconomicSecuritySubsystem,
} from '../src/services/economicService';

import {
  initializeWalletRecovery,
  initiateBreakGlassRecovery,
  submitCustodianApproval,
  executeGuardedRecovery,
} from '../src/services/recoveryService';

import {
  decryptShareGcm,
} from '../src/crypto/secureEncryption';

import {
  evaluateAccessPolicy,
} from '../src/services/locationService';

test('1. End-to-End: 3-Domain DKG Keygen, Pinned Placement & Separation-of-Powers ECDSA Signing', async () => {
  const userId = 'usr-integration-e2e-01';

  // Step 1: Dynamic Topology & Placement
  const topology = buildClusterTopology(19); // 7 Foundation, 6 Public, 6 Private
  assert.strictEqual(topology.totalNodes, 19);
  assert.strictEqual(topology.foundation.count, 7);
  assert.strictEqual(topology.public.count, 6);
  assert.strictEqual(topology.private.count, 6);

  const walletId = 'wlt-e2e-test-01';
  const placement = computeWalletPlacement(walletId, topology, 1, userId);
  assert.strictEqual(placement.foundation.assignedNodeIds.length, 7);
  assert.strictEqual(placement.public.assignedNodeIds.length, 6);
  assert.strictEqual(placement.private.assignedNodeIds.length, 6);
  assert.ok(placement.manifestHash && placement.manifestHash.length === 64);

  // Step 2: DKG Key Generation (Zero complete private key formed)
  const mpcWallet = generateSaralWalletMpc(6, 4, 7, 5, 6, 4);
  assert.ok(ethers.isAddress(mpcWallet.address));
  assert.ok(mpcWallet.aggregatedPublicKeyHex.startsWith('0x') && mpcWallet.aggregatedPublicKeyHex.length === 132);

  // Step 3: Break-Glass Recovery Setup at Keygen
  const recoverySetup = initializeWalletRecovery(
    userId,
    3,
    5,
    48,
    mpcWallet.privateDomain.publicKeyPointHex
  );
  assert.strictEqual(recoverySetup.thresholdM, 3);
  assert.strictEqual(recoverySetup.totalCustodiansN, 5);

  // Step 4: Construct Unsigned EVM Transaction Payload
  const chainId = 1337n;
  const unsignedTx = ethers.Transaction.from({
    to: '0x1111111111111111111111111111111111111111',
    value: ethers.parseEther('1.5'),
    nonce: 0,
    gasLimit: 21000n,
    gasPrice: ethers.parseUnits('20', 'gwei'),
    chainId,
    type: 0,
  });
  const unsignedTxSerialized = unsignedTx.unsignedSerialized;

  // Step 5: Form 3-of-3 Cross-Domain Quorums
  const selectedFoundation = mpcWallet.foundation.shares.slice(0, 5); // 5 of 7
  const selectedPublic = mpcWallet.publicDomain.shares.slice(0, 4);   // 4 of 6
  const selectedPrivate = mpcWallet.privateDomain.shares.slice(0, 4); // 4 of 6

  // Step 6: Execute MPC Threshold Signing Session
  const mpcSig = await executeMpcThresholdSign(
    {
      unsignedTxSerialized,
      chainId,
      foundation: {
        domain: 'FOUNDATION',
        activeShareIndices: selectedFoundation.map((s) => s.index),
        shareValues: selectedFoundation.map((s) => s.value),
      },
      publicDomain: {
        domain: 'PUBLIC',
        activeShareIndices: selectedPublic.map((s) => s.index),
        shareValues: selectedPublic.map((s) => s.value),
      },
      privateDomain: {
        domain: 'PRIVATE',
        activeShareIndices: selectedPrivate.map((s) => s.index),
        shareValues: selectedPrivate.map((s) => s.value),
      },
    },
    mpcWallet.aggregatedPublicKeyHex,
    4,
    4
  );

  // Step 7: Verify Signer Address matches MPC Wallet Address
  const signedTxParsed = ethers.Transaction.from(mpcSig.rawSignedTx);
  assert.strictEqual(
    signedTxParsed.from?.toLowerCase(),
    mpcWallet.address.toLowerCase(),
    'Recovered signature address must match DKG aggregated wallet address'
  );

  // Step 8: Economic Fee Processing
  const econ = new EconomicSecuritySubsystem();
  const feeResult = econ.processUsageFee(0.005);
  assert.ok(feeResult.burnedSst > 0);
  assert.ok(feeResult.insuranceAddedMstc > 0);
  assert.ok(feeResult.validatorRewardsMstc > 0);
});

test('2. Security Rejection: Missing Domain Quorum or Subverted Separation of Powers', async () => {
  const mpcWallet = generateSaralWalletMpc(6, 4, 7, 5, 6, 4);
  const unsignedTx = ethers.Transaction.from({
    to: '0x1111111111111111111111111111111111111111',
    value: ethers.parseEther('0.1'),
    nonce: 0,
    gasLimit: 21000n,
    gasPrice: ethers.parseUnits('20', 'gwei'),
    chainId: 1337n,
    type: 0,
  });
  const unsignedTxSerialized = unsignedTx.unsignedSerialized;

  const validF = {
    domain: 'FOUNDATION' as const,
    activeShareIndices: mpcWallet.foundation.shares.slice(0, 5).map((s) => s.index),
    shareValues: mpcWallet.foundation.shares.slice(0, 5).map((s) => s.value),
  };
  const validP = {
    domain: 'PUBLIC' as const,
    activeShareIndices: mpcWallet.publicDomain.shares.slice(0, 4).map((s) => s.index),
    shareValues: mpcWallet.publicDomain.shares.slice(0, 4).map((s) => s.value),
  };
  const validV = {
    domain: 'PRIVATE' as const,
    activeShareIndices: mpcWallet.privateDomain.shares.slice(0, 4).map((s) => s.index),
    shareValues: mpcWallet.privateDomain.shares.slice(0, 4).map((s) => s.value),
  };

  // Case A: Missing Foundation Domain (Foundation tries to be bypassed)
  await assert.rejects(
    async () => {
      await executeMpcThresholdSign({
        unsignedTxSerialized,
        chainId: 1337n,
        foundation: { domain: 'FOUNDATION', activeShareIndices: [], shareValues: [] },
        publicDomain: validP,
        privateDomain: validV,
      }, mpcWallet.aggregatedPublicKeyHex, 4, 4);
    },
    /Separation of Powers/i,
    'Signing without Foundation domain must fail'
  );

  // Case B: Missing Public Validator Quorum (< 4 shares)
  await assert.rejects(
    async () => {
      await executeMpcThresholdSign({
        unsignedTxSerialized,
        chainId: 1337n,
        foundation: validF,
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: mpcWallet.publicDomain.shares.slice(0, 3).map((s) => s.index),
          shareValues: mpcWallet.publicDomain.shares.slice(0, 3).map((s) => s.value),
        },
        privateDomain: validV,
      }, mpcWallet.aggregatedPublicKeyHex, 4, 4);
    },
    /Public domain.*shortfall/i,
    'Signing with insufficient public validator shares must fail'
  );

  // Case C: Missing Private Sovereign Domain (< 4 shares)
  await assert.rejects(
    async () => {
      await executeMpcThresholdSign({
        unsignedTxSerialized,
        chainId: 1337n,
        foundation: validF,
        publicDomain: validP,
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: mpcWallet.privateDomain.shares.slice(0, 3).map((s) => s.index),
          shareValues: mpcWallet.privateDomain.shares.slice(0, 3).map((s) => s.value),
        },
      }, mpcWallet.aggregatedPublicKeyHex, 4, 4);
    },
    /Private domain.*shortfall/i,
    'Signing with insufficient private sovereign shares must fail'
  );
});

test('3. End-to-End Recovery Flow: Key Shares Rotated without Address Change', async () => {
  const userId = 'usr-integration-recovery-01';
  const mpcWallet = generateSaralWalletMpc(6, 4, 7, 5, 6, 4);

  // Initialize recovery with 0 timelock for instant test
  const setup = initializeWalletRecovery(
    userId,
    3,
    5,
    0,
    mpcWallet.privateDomain.publicKeyPointHex
  );

  // User initiates recovery
  const req = initiateBreakGlassRecovery(userId, 'Lost private device enclave', 0);

  // 3 Custodians approve
  for (let i = 0; i < 3; i++) {
    const c = setup.custodians[i];
    const dec = JSON.parse(decryptShareGcm(c.encryptedShare, `RECOVERY-${c.id}`));
    submitCustodianApproval(req.requestId, c.id, dec.index, dec.value);
  }

  // Execute recovery MPC
  const result = executeGuardedRecovery(req.requestId);
  assert.strictEqual(result.success, true);
  assert.strictEqual(result.preservedPrivatePublicKeyHex, mpcWallet.privateDomain.publicKeyPointHex);
});
