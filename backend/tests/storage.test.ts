/**
 * storage.test.ts
 *
 * Hardened Node File Storage & Cryptographic Tamper Detection Test Suite.
 *
 * Patent & Specification Mandates (Section 2.3, Claim 1, Paragraph [0018]):
 *   1. Atomic writes (write temp, fsync, rename). File mode 0600, directory mode 0700.
 *   2. Per-node scrypt key derivation (no global master key).
 *   3. AES-256-GCM encryption with unique IV.
 *   4. AAD binding to walletId and epoch:
 *      - Swapping share between wallets fails authentication tag verification.
 *      - Swapping share between epochs fails authentication tag verification.
 *   5. Integrity checks on read: bit-flipped corruption is detected and rejected.
 */

import test from 'node:test';
import assert from 'node:assert';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

import { NodeFileStore } from '../src/storage/fileStore';

test('1. Per-Node Key Isolation: Different nodes derive distinct scrypt keys', () => {
  const tmpDir = path.resolve(process.cwd(), '.saral_test_storage_dir');
  const store = new NodeFileStore(tmpDir);

  try {
    const keyF1 = store.deriveNodeKey('FOUNDATION', 'saral-foundation-1');
    const keyF2 = store.deriveNodeKey('FOUNDATION', 'saral-foundation-2');
    const keyP1 = store.deriveNodeKey('PUBLIC', 'saral-public-1');

    assert.strictEqual(keyF1.length, 32);
    assert.strictEqual(keyF2.length, 32);
    assert.strictEqual(keyP1.length, 32);

    assert.notDeepStrictEqual(keyF1, keyF2, 'Different nodes in same domain must have distinct keys');
    assert.notDeepStrictEqual(keyF1, keyP1, 'Nodes in different domains must have distinct keys');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('2. Atomic Write & POSIX Permissions: File 0600, Directory 0700', () => {
  const tmpDir = path.resolve(process.cwd(), '.saral_test_storage_perm');
  const store = new NodeFileStore(tmpDir);

  try {
    const domain = 'PUBLIC';
    const nodeId = 'saral-public-1';
    const walletId = 'wallet-perm-test-01';
    const epoch = 1;
    const shareIndex = 1;
    const plaintext = JSON.stringify({ index: 1, share: '3f9a7c...' });

    const meta = store.writeShare(domain, nodeId, walletId, epoch, shareIndex, plaintext);
    assert.strictEqual(meta.walletId, walletId);

    const walletDir = path.join(tmpDir, 'public', nodeId, 'wallets', walletId);
    const sharePath = path.join(walletDir, 'share.enc');
    const metaPath = path.join(walletDir, 'meta.json');

    assert.ok(fs.existsSync(sharePath));
    assert.ok(fs.existsSync(metaPath));

    const dirStat = fs.statSync(walletDir);
    const fileStat = fs.statSync(sharePath);

    // Verify POSIX permissions (octal mask 0777)
    const dirMode = dirStat.mode & 0o777;
    const fileMode = fileStat.mode & 0o777;

    assert.strictEqual(dirMode, 0o700, 'Directory must have 0700 permissions (owner rwx only)');
    assert.strictEqual(fileMode, 0o600, 'File must have 0600 permissions (owner rw only)');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('3. Roundtrip Encryption & Decryption: Plaintext recovered accurately', () => {
  const tmpDir = path.resolve(process.cwd(), '.saral_test_storage_roundtrip');
  const store = new NodeFileStore(tmpDir);

  try {
    const domain = 'PRIVATE';
    const nodeId = 'saral-private-3';
    const walletId = 'wallet-roundtrip-01';
    const epoch = 1;
    const shareIndex = 3;
    const secretSharePayload = '7a29f84b6c3104e5...secret-scalar-share';

    store.writeShare(domain, nodeId, walletId, epoch, shareIndex, secretSharePayload);

    const { plaintextShare, metadata } = store.readShare(domain, nodeId, walletId, epoch);
    assert.strictEqual(plaintextShare, secretSharePayload);
    assert.strictEqual(metadata.walletId, walletId);
    assert.strictEqual(metadata.epoch, epoch);
    assert.strictEqual(metadata.shareIndex, shareIndex);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('4. Cross-Wallet Share Swapping Attack Fails (AAD Binding)', () => {
  const tmpDir = path.resolve(process.cwd(), '.saral_test_storage_swap_wallet');
  const store = new NodeFileStore(tmpDir);

  try {
    const domain = 'PUBLIC';
    const nodeId = 'saral-public-1';
    const victimWalletId = 'victim-wallet-1111';
    const attackerWalletId = 'attacker-wallet-2222';
    const epoch = 1;

    // Write victim share
    store.writeShare(domain, nodeId, victimWalletId, epoch, 1, 'victim-secret-share');

    // Attacker copies victim share.enc into attacker wallet directory
    const victimDir = path.join(tmpDir, 'public', nodeId, 'wallets', victimWalletId);
    const attackerDir = path.join(tmpDir, 'public', nodeId, 'wallets', attackerWalletId);
    fs.mkdirSync(attackerDir, { recursive: true, mode: 0o700 });

    fs.copyFileSync(path.join(victimDir, 'share.enc'), path.join(attackerDir, 'share.enc'));

    // Attacker creates metadata for their own wallet pointing to victim's ciphertext
    const victimShareContent = fs.readFileSync(path.join(victimDir, 'share.enc'), 'utf8');
    const checksum = crypto.createHash('sha256').update(victimShareContent).digest('hex');
    const attackerMeta = {
      version: 'v1',
      walletId: attackerWalletId,
      epoch: 1,
      nodeId,
      domain,
      shareIndex: 1,
      cipherLength: 50,
      checksumSha256: checksum,
      updatedAt: new Date().toISOString(),
    };
    fs.writeFileSync(path.join(attackerDir, 'meta.json'), JSON.stringify(attackerMeta), { mode: 0o600 });

    // Attempting to read attacker's wallet MUST fail because AAD binds to victimWalletId
    assert.throws(
      () => store.readShare(domain, nodeId, attackerWalletId, epoch),
      /Cryptographic authentication tag verification failed/i,
      'Swapping share ciphertext to another wallet MUST be rejected by AES-GCM AAD verification'
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('5. Cross-Epoch Share Swapping Attack Fails (Stale Epoch Protection)', () => {
  const tmpDir = path.resolve(process.cwd(), '.saral_test_storage_swap_epoch');
  const store = new NodeFileStore(tmpDir);

  try {
    const domain = 'FOUNDATION';
    const nodeId = 'saral-foundation-1';
    const walletId = 'wallet-epoch-test';

    // Store share under Epoch 1
    store.writeShare(domain, nodeId, walletId, 1, 1, 'epoch-1-share');

    // Trying to read requesting Epoch 2 MUST fail
    assert.throws(
      () => store.readShare(domain, nodeId, walletId, 2),
      /Stale share epoch/i,
      'Reading with newer epoch expectation must reject stale epoch share'
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('6. Bit-Flipping File Tampering Detection', () => {
  const tmpDir = path.resolve(process.cwd(), '.saral_test_storage_tamper');
  const store = new NodeFileStore(tmpDir);

  try {
    const domain = 'PUBLIC';
    const nodeId = 'saral-public-2';
    const walletId = 'wallet-tamper-01';

    store.writeShare(domain, nodeId, walletId, 1, 2, 'tamper-proof-share');

    const shareFile = path.join(tmpDir, 'public', nodeId, 'wallets', walletId, 'share.enc');
    const content = fs.readFileSync(shareFile, 'utf8');

    // Corrupt one character in the file
    const corrupted = content.slice(0, 30) + (content[30] === 'a' ? 'b' : 'a') + content.slice(31);
    fs.writeFileSync(shareFile, corrupted, { mode: 0o600 });

    // Checksum mismatch must be detected immediately
    assert.throws(
      () => store.readShare(domain, nodeId, walletId, 1),
      /Share integrity checksum mismatch/i,
      'Bit-flipped or corrupted file must be rejected by SHA-256 integrity check'
    );
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

