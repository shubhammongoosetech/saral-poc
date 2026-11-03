import test from 'node:test';
import assert from 'node:assert';
import {
  initializeWalletRecovery,
  initiateBreakGlassRecovery,
  cancelRecoveryRequest,
  submitCustodianApproval,
  executeGuardedRecovery,
  getRecoveryAuditLogs,
} from '../src/services/recoveryService';
import { decryptShareGcm } from '../src/crypto/secureEncryption';

test('1. Recovery Initialization: Custodians and Commitments Generated', () => {
  const userId = 'user-recovery-test-001';
  const setup = initializeWalletRecovery(userId, 3, 5, 48);

  assert.strictEqual(setup.thresholdM, 3);
  assert.strictEqual(setup.totalCustodiansN, 5);
  assert.strictEqual(setup.custodians.length, 5);
  assert.strictEqual(setup.commitments.length, 3);

  // Each custodian share is encrypted with domain separation
  for (const c of setup.custodians) {
    assert.ok(c.encryptedShare.startsWith('v1:RECOVERY-'));
    const decrypted = decryptShareGcm(c.encryptedShare, `RECOVERY-${c.id}`);
    const parsed = JSON.parse(decrypted);
    assert.ok(parsed.index >= 1 && parsed.index <= 5);
    assert.ok(parsed.value && parsed.value.length === 64);
  }
});

test('2. Guarded Timelock Enforcement: Early recovery attempts are strictly rejected', () => {
  const userId = 'user-recovery-test-002';
  const setup = initializeWalletRecovery(userId, 3, 5, 48);

  // Initiate recovery with 48 hours timelock
  const req = initiateBreakGlassRecovery(userId, 'Lost phone hardware device', 48);

  // Submit approvals for 3 custodians
  for (let i = 0; i < 3; i++) {
    const c = setup.custodians[i];
    const dec = JSON.parse(decryptShareGcm(c.encryptedShare, `RECOVERY-${c.id}`));
    submitCustodianApproval(req.requestId, c.id, dec.index, dec.value);
  }

  // Attempt to execute immediately (timelock has 48 hours remaining)
  assert.throws(() => {
    executeGuardedRecovery(req.requestId);
  }, /Mandatory timelock has not expired yet/);
});

test('3. Custodian Quorum Enforcement: Insufficient approvals (< m) rejected', () => {
  const userId = 'user-recovery-test-003';
  const setup = initializeWalletRecovery(userId, 3, 5, 0); // 0 hours timelock for unit testing

  const req = initiateBreakGlassRecovery(userId, 'Testing quorum', 0);

  // Submit approvals for only 2 custodians (need 3)
  for (let i = 0; i < 2; i++) {
    const c = setup.custodians[i];
    const dec = JSON.parse(decryptShareGcm(c.encryptedShare, `RECOVERY-${c.id}`));
    submitCustodianApproval(req.requestId, c.id, dec.index, dec.value);
  }

  assert.throws(() => {
    executeGuardedRecovery(req.requestId);
  }, /Insufficient custodian quorum: require 3 approvals, got 2/);
});

test('4. Challenge & Abort: Sovereign user cancels unauthorized recovery attempt', () => {
  const userId = 'user-recovery-test-004';
  initializeWalletRecovery(userId, 3, 5, 48);

  const req = initiateBreakGlassRecovery(userId, 'Attacker simulation', 48);
  assert.strictEqual(req.state, 'PENDING_TIMELOCK');

  // User detects fraudulent attempt and aborts
  const cancelled = cancelRecoveryRequest(userId, req.requestId, 'Fraudulent attempt by compromised email');
  assert.strictEqual(cancelled.state, 'CHALLENGED_CANCELLED');

  // Execution fails on cancelled request
  assert.throws(() => {
    executeGuardedRecovery(req.requestId);
  }, /Insufficient custodian quorum/);
});

test('5. Authorized Recovery Success: Timelock expired & Quorum met restores Private Domain via MPC', () => {
  const userId = 'user-recovery-test-005';
  const setup = initializeWalletRecovery(userId, 3, 5, 0); // 0 timelock for testing

  const req = initiateBreakGlassRecovery(userId, 'Legitimate sovereign key recovery', 0);

  // Submit approvals for 3 custodians (1, 3, 5)
  const custodiansToUse = [setup.custodians[0], setup.custodians[2], setup.custodians[4]];
  for (const c of custodiansToUse) {
    const dec = JSON.parse(decryptShareGcm(c.encryptedShare, `RECOVERY-${c.id}`));
    const res = submitCustodianApproval(req.requestId, c.id, dec.index, dec.value);
    assert.strictEqual(res.success, true);
  }

  // Execute Guarded Recovery
  const execResult = executeGuardedRecovery(req.requestId);
  assert.strictEqual(execResult.success, true);
  assert.ok(execResult.rotatedPrivateDomainPublicCommitment.startsWith('02') || execResult.rotatedPrivateDomainPublicCommitment.startsWith('03'));

  // Verify Audit Log records
  const auditLogs = getRecoveryAuditLogs(userId);
  assert.ok(auditLogs.length >= 4, 'Audit trail must contain all lifecycle events');
  const eventTypes = auditLogs.map((l) => l.eventType);
  assert.ok(eventTypes.includes('RECOVERY_SECRET_INITIALIZED'));
  assert.ok(eventTypes.includes('RECOVERY_REQUESTED'));
  assert.ok(eventTypes.includes('CUSTODIAN_APPROVAL_SUBMITTED'));
  assert.ok(eventTypes.includes('RECOVERY_MPC_EXECUTED'));
});

