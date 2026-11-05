/**
 * recovery.test.ts
 *
 * Guarded Break-Glass Recovery Subsystem Test Suite.
 *
 * Patent & Specification Mandates (Claims 2, 3, Paragraphs [0020]-[0021]):
 *   1. Recovery secret generated at key-generation time, independent of primary structure.
 *   2. Custodian quorum (m-of-N threshold).
 *   3. Mandatory timelock challenge window (early execution strictly blocked).
 *   4. Sovereign user challenge / abort capability during timelock.
 *   5. Homomorphic custodian threshold verification in exponent (no central secret reconstruction).
 *   6. Proactive Secret Sharing (PSS) zero-polynomial share refresh:
 *      Rotates compromised node shares while preserving public key & wallet address.
 *   7. Immutable audit logging of all recovery lifecycle actions.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';

process.env.NODE_ENV = 'test';

// Clean test state
const testRecoveryState = path.resolve(process.cwd(), '.saral_registry', 'recovery_state.json');
if (fs.existsSync(testRecoveryState)) {
  try { fs.unlinkSync(testRecoveryState); } catch {}
}

import {
  initializeWalletRecovery,
  initiateBreakGlassRecovery,
  submitCustodianApproval,
  cancelRecoveryRequest,
  executeGuardedRecovery,
  getRecoveryAuditLogs,
} from '../src/services/recoveryService';

import {
  decryptShareGcm,
} from '../src/crypto/secureEncryption';

import {
  randomScalar,
  scalarMultiplyG,
  scalarToHex,
  CURVE_ORDER,
  modN,
} from '../src/crypto/secp256k1Math';

import {
  splitSecretField,
  reconstructSecretField,
  generateZeroPolynomial,
  evaluateZeroPolynomial,
  proactiveRefreshShare,
  refreshFeldmanCommitments,
  verifyShareWithCommitments,
} from '../src/crypto/shamirField';

test('1. Break-Glass Recovery Initialization at Keygen Time', () => {
  const userId = 'usr-test-init-01';
  const dummyPrivatePubKeyHex = scalarMultiplyG(randomScalar()).toHex(true);

  // Initialize with 3-of-5 threshold, 48 hours timelock
  const setup = initializeWalletRecovery(userId, 3, 5, 48, dummyPrivatePubKeyHex);

  assert.strictEqual(setup.userId, userId);
  assert.strictEqual(setup.thresholdM, 3);
  assert.strictEqual(setup.totalCustodiansN, 5);
  assert.strictEqual(setup.timelockDurationHours, 48);
  assert.strictEqual(setup.custodians.length, 5);
  assert.strictEqual(setup.commitments.length, 3, 'Feldman commitments equal to threshold m=3');

  // Verify each custodian received an encrypted recovery share
  for (const c of setup.custodians) {
    assert.ok(c.id.startsWith('custodian-'));
    assert.ok(c.encryptedShare && c.encryptedShare.length > 20);
    // Can decrypt with domain key
    const decrypted = JSON.parse(decryptShareGcm(c.encryptedShare, `RECOVERY-${c.id}`));
    assert.ok(decrypted.index >= 1 && decrypted.index <= 5);
    assert.ok(decrypted.value && decrypted.value.length === 64);
  }

  // Audit trail recorded initialization
  const logs = getRecoveryAuditLogs(userId);
  assert.ok(logs.some((l) => l.eventType === 'RECOVERY_SECRET_INITIALIZED'));
});

test('2. Mandatory Timelock Delay Enforcement (Early Execution Blocked)', () => {
  const userId = 'usr-test-timelock-01';
  const dummyPubHex = scalarMultiplyG(randomScalar()).toHex(true);
  const setup = initializeWalletRecovery(userId, 3, 5, 24, dummyPubHex);

  // Initiate recovery with 24-hour timelock
  const req = initiateBreakGlassRecovery(userId, 'Lost all private devices in hardware failure', 24);
  assert.strictEqual(req.state, 'PENDING_TIMELOCK');
  assert.ok(new Date(req.timelockExpiresAt).getTime() > Date.now() + 23 * 3600 * 1000);

  // Submit 3 valid custodian approvals (meeting quorum)
  for (let i = 0; i < 3; i++) {
    const c = setup.custodians[i];
    const dec = JSON.parse(decryptShareGcm(c.encryptedShare, `RECOVERY-${c.id}`));
    submitCustodianApproval(req.requestId, c.id, dec.index, dec.value);
  }

  // Attempt to execute immediately before timelock expiry -> MUST THROW
  assert.throws(
    () => executeGuardedRecovery(req.requestId),
    /Mandatory timelock has not expired yet/i,
    'Early recovery before timelock expiry must be strictly rejected'
  );
});

test('3. Sovereign User Challenge / Cancellation Window', () => {
  const userId = 'usr-test-cancel-01';
  const dummyPubHex = scalarMultiplyG(randomScalar()).toHex(true);
  initializeWalletRecovery(userId, 3, 5, 48, dummyPubHex);

  // Attacker or unauthorized party initiates recovery
  const req = initiateBreakGlassRecovery(userId, 'Unauthorized suspicious request', 48);
  assert.strictEqual(req.state, 'PENDING_TIMELOCK');

  // Sovereign owner receives alert and challenges/cancels during timelock
  const cancelled = cancelRecoveryRequest(userId, req.requestId, 'Fraudulent recovery attempt detected');
  assert.strictEqual(cancelled.state, 'CHALLENGED_CANCELLED');

  // Any subsequent execution must be rejected
  assert.throws(
    () => executeGuardedRecovery(req.requestId),
    /Recovery request was challenged and cancelled/i,
    'Cancelled recovery request can never be executed'
  );

  // Audit trail records user cancellation
  const logs = getRecoveryAuditLogs(userId);
  assert.ok(logs.some((l) => l.eventType === 'RECOVERY_CANCELLED_BY_USER'));
});

test('4. Custodian Quorum Enforcement & Tamper Detection', () => {
  const userId = 'usr-test-quorum-01';
  const dummyPubHex = scalarMultiplyG(randomScalar()).toHex(true);
  const setup = initializeWalletRecovery(userId, 3, 5, 0, dummyPubHex); // 0 hours timelock for instant test

  const req = initiateBreakGlassRecovery(userId, 'Quorum and tamper verification', 0);

  // Only 2 custodians submit (threshold is 3)
  for (let i = 0; i < 2; i++) {
    const c = setup.custodians[i];
    const dec = JSON.parse(decryptShareGcm(c.encryptedShare, `RECOVERY-${c.id}`));
    submitCustodianApproval(req.requestId, c.id, dec.index, dec.value);
  }

  // Insufficient quorum fails
  assert.throws(
    () => executeGuardedRecovery(req.requestId),
    /Insufficient custodian quorum: require 3 approvals, got 2/i
  );

  // Duplicate submission by same custodian fails
  const c0 = setup.custodians[0];
  const dec0 = JSON.parse(decryptShareGcm(c0.encryptedShare, `RECOVERY-${c0.id}`));
  assert.throws(
    () => submitCustodianApproval(req.requestId, c0.id, dec0.index, dec0.value),
    /already submitted approval/i
  );

  // Invalid / corrupted share submission fails commitment verification
  const c2 = setup.custodians[2];
  const corruptedValue = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  submitCustodianApproval(req.requestId, c2.id, 3, corruptedValue);

  assert.throws(
    () => executeGuardedRecovery(req.requestId),
    /failed Feldman commitment verification/i,
    'Tampered custodian recovery share must be detected and rejected'
  );
});

test('5. Proactive Secret Sharing (PSS): Zero-Polynomial Share Refresh Preserves Public Key & Address', () => {
  // Patent claim 3: Recovery never reconstructs the private key: it re-shares to new nodes.
  // Proactive Secret Sharing (PSS) mathematical proof:
  // Secret x_U shared with degree (t-1) polynomial f(z) = x_U + a_1*z + ... + a_{t-1}*z^{t-1}.
  // Generate zero-polynomial h(z) where h(0) = 0: h(z) = b_1*z + ... + b_{t-1}*z^{t-1}.
  // Node j computes new share s_j' = s_j + h(j) mod n.
  // Reconstructed secret: f'(0) = f(0) + h(0) = x_U + 0 = x_U (mod n).
  // Public key Q_U = x_U * G and EVM address remain strictly UNCHANGED.

  const x_U = randomScalar();
  const originalPubKey = scalarMultiplyG(x_U);
  const n = 6;
  const t = 4;

  const originalVss = splitSecretField(x_U, n, t);

  // Verify original secret reconstruction from any t shares
  const subsetShares = originalVss.shares.slice(0, t);
  const recoveredSecret = reconstructSecretField(subsetShares, t);
  assert.strictEqual(recoveredSecret, x_U, 'Original secret reconstructs from t shares');

  // Generate zero-polynomial of degree t-1
  const zeroPoly = generateZeroPolynomial(t);
  assert.strictEqual(zeroPoly[0], 0n, 'Constant coefficient h(0) must be 0n');

  // Refresh all shares
  const refreshedShares = originalVss.shares.map((share) => {
    return proactiveRefreshShare(share, zeroPoly);
  });

  // Verify refreshed shares are strictly DIFFERENT from original shares (old shares invalidated)
  for (let i = 0; i < n; i++) {
    assert.notStrictEqual(
      refreshedShares[i].value,
      originalVss.shares[i].value,
      `Share ${i + 1} must be refreshed to a new scalar`
    );
  }

  // Refresh Feldman commitments: C_0' = C_0, C_k' = C_k + b_k*G
  const refreshedCommitments = refreshFeldmanCommitments(originalVss.commitments, zeroPoly);
  assert.strictEqual(
    refreshedCommitments[0],
    originalVss.commitments[0],
    'Constant commitment C_0 (public key point) must be 100% IDENTICAL'
  );

  // Each refreshed share satisfies refreshed commitments
  for (const refreshedShare of refreshedShares) {
    const valid = verifyShareWithCommitments(refreshedShare, refreshedCommitments);
    assert.ok(valid, `Refreshed share ${refreshedShare.index} must verify against refreshed commitments`);
  }

  // Reconstructing from any t refreshed shares gives the exact SAME master secret x_U!
  const recoveredFromRefreshed = reconstructSecretField(refreshedShares.slice(1, 1 + t), t);
  assert.strictEqual(
    recoveredFromRefreshed,
    x_U,
    'Reconstructed secret after PSS zero-polynomial refresh is strictly identical'
  );

  // The public key point Q_U = x_U * G is identical
  const recoveredPubKey = scalarMultiplyG(recoveredFromRefreshed);
  assert.strictEqual(recoveredPubKey.toHex(true), originalPubKey.toHex(true));
});

test('6. Full End-to-End Guarded Recovery Execution with 0-Hour Timelock', () => {
  const userId = 'usr-test-e2e-recovery-01';
  const privateDomainScalar = randomScalar();
  const privatePubKeyHex = scalarMultiplyG(privateDomainScalar).toHex(true);

  // Initialize recovery
  const setup = initializeWalletRecovery(userId, 3, 5, 0, privatePubKeyHex);

  // Initiate request with 0 timelock for execution
  const req = initiateBreakGlassRecovery(userId, 'Hardware replacement recovery', 0);

  // 3 of 5 custodians authorize
  for (let i = 0; i < 3; i++) {
    const c = setup.custodians[i];
    const dec = JSON.parse(decryptShareGcm(c.encryptedShare, `RECOVERY-${c.id}`));
    submitCustodianApproval(req.requestId, c.id, dec.index, dec.value);
  }

  // Execute recovery
  const result = executeGuardedRecovery(req.requestId);
  assert.strictEqual(result.success, true);
  assert.ok(result.message.includes('Proactive Secret Sharing'));
  assert.strictEqual(result.preservedPrivatePublicKeyHex, privatePubKeyHex);

  // State is now EXECUTED
  assert.throws(
    () => executeGuardedRecovery(req.requestId),
    /already been executed/i,
    'Cannot execute an already-executed recovery request'
  );

  // Verify full audit trail
  const logs = getRecoveryAuditLogs(userId);
  const events = logs.map((l) => l.eventType);
  assert.ok(events.includes('RECOVERY_SECRET_INITIALIZED'));
  assert.ok(events.includes('RECOVERY_REQUESTED'));
  assert.ok(events.includes('CUSTODIAN_APPROVAL_SUBMITTED'));
  assert.ok(events.includes('RECOVERY_MPC_EXECUTED'));
});
