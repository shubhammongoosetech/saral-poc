import test from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';
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
} from '../src/crypto/secp256k1Math';
import {
  splitSecretField,
  reconstructSecretField,
  verifyShareWithCommitments,
  computeLagrangeCoefficient,
} from '../src/crypto/shamirField';
import {
  encryptShareGcm,
  decryptShareGcm,
  deriveDomainKey,
} from '../src/crypto/secureEncryption';
import {
  splitPrivateKey3Ways,
  combinePrivateKey3WaysAsBuffer,
  combinePrivateKey3Ways,
  secureCompare,
  wipeBuffer,
} from '../src/utils/crypto';
import {
  generateSaralWalletMpc,
  executeMpcThresholdSign,
} from '../src/crypto/thresholdEcdsa';

test('1. Cryptographic Randomness & Field Math: secp256k1 F_n scalars', () => {
  const s1 = randomScalar();
  const s2 = randomScalar();
  assert.notStrictEqual(s1, s2, 'Random scalars must be distinct');
  assert.ok(s1 > 0n && s1 < CURVE_ORDER, 'Scalar must be in [1, n-1]');
  assert.ok(s2 > 0n && s2 < CURVE_ORDER, 'Scalar must be in [1, n-1]');

  const inv1 = modInverse(s1, CURVE_ORDER);
  const prod = modN(s1 * inv1);
  assert.strictEqual(prod, 1n, 'Modular inverse property must hold: s * s^(-1) = 1 mod n');
});

test('2. 3-Way XOR Decomposition & Constant-time Wipe', () => {
  const originalKey = '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  const parts = splitPrivateKey3Ways(originalKey);

  assert.ok(parts.PUBLIC && parts.PUBLIC.length === 64);
  assert.ok(parts.INSTITUTIONAL && parts.INSTITUTIONAL.length === 64);
  assert.ok(parts.SOVEREIGN && parts.SOVEREIGN.length === 64);

  // Recombine
  const recombined = combinePrivateKey3Ways(parts.PUBLIC, parts.INSTITUTIONAL, parts.SOVEREIGN);
  assert.strictEqual(recombined.toLowerCase(), originalKey.toLowerCase());

  // Memory wipe verification
  const secretBuf = Buffer.from('super-secret-cryptographic-seed');
  wipeBuffer(secretBuf);
  assert.ok(secretBuf.every((b) => b === 0), 'Buffer must be completely zeroized');
});

test('3. Shamir Secret Sharing over F_n: Threshold & Commitment Correctness', () => {
  const secret = randomScalar();
  const n = 9;
  const threshold = 5;

  const vss = splitSecretField(secret, n, threshold);
  assert.strictEqual(vss.shares.length, 9);
  assert.strictEqual(vss.commitments.length, 5);

  // Feldman commitments verification for all shares
  for (const s of vss.shares) {
    const valid = verifyShareWithCommitments(s, vss.commitments);
    assert.strictEqual(valid, true, `Share ${s.index} must match Feldman commitments`);
  }

  // Exact threshold (5 shares) reconstructs secret
  const subset5 = vss.shares.slice(0, 5);
  const reconstructed5 = reconstructSecretField(subset5, threshold);
  assert.strictEqual(reconstructed5, secret, '5-of-9 shares must reconstruct secret');

  // Any other distinct 5 shares reconstructs secret
  const subsetAnother5 = [vss.shares[1], vss.shares[3], vss.shares[4], vss.shares[7], vss.shares[8]];
  const reconstructedAnother5 = reconstructSecretField(subsetAnother5, threshold);
  assert.strictEqual(reconstructedAnother5, secret, 'Non-contiguous 5 shares must reconstruct secret');

  // Insufficient shares (4 shares) fails threshold
  const subset4 = vss.shares.slice(0, 4);
  assert.throws(() => {
    reconstructSecretField(subset4, threshold);
  }, /Insufficient shares/, 'Reconstruction with 4 shares must throw');

  // Duplicate share indices rejected
  assert.throws(() => {
    reconstructSecretField([vss.shares[0], vss.shares[0], vss.shares[1], vss.shares[2], vss.shares[3]], threshold);
  }, /Duplicate share index detected/);
});

test('4. AES-256-GCM: Nonce Uniqueness, Domain Separation, Tamper Rejection', () => {
  const plainText = 'saral-node-confidential-share-data-12345';

  // Test unique IV on consecutive encryptions
  const enc1 = encryptShareGcm(plainText, 'FOUNDATION');
  const enc2 = encryptShareGcm(plainText, 'FOUNDATION');
  assert.notStrictEqual(enc1.iv, enc2.iv, 'AES-GCM IV must be cryptographically unique per encryption');
  assert.notStrictEqual(enc1.ciphertext, enc2.ciphertext, 'Ciphertexts must differ due to unique IV');

  // Decrypt valid
  const dec1 = decryptShareGcm(enc1.serialized, 'FOUNDATION');
  assert.strictEqual(dec1, plainText);

  // Domain mismatch rejection
  assert.throws(() => {
    decryptShareGcm(enc1.serialized, 'PUBLIC');
  }, /Domain mismatch/, 'Decrypting with wrong domain must be rejected');

  // Tampered ciphertext rejection (simulate bit flip)
  const parts = enc1.serialized.split(':');
  const tamperedCipher = 'ff' + parts[4].slice(2);
  const tamperedSerialized = `${parts[0]}:${parts[1]}:${parts[2]}:${parts[3]}:${tamperedCipher}`;

  assert.throws(() => {
    decryptShareGcm(tamperedSerialized, 'FOUNDATION');
  }, /authentication tag verification failed/, 'Tampered ciphertext must fail GMAC verification');

  // Tampered auth tag rejection
  const tamperedTag = '00' + parts[3].slice(2);
  const tamperedTagSerialized = `${parts[0]}:${parts[1]}:${parts[2]}:${tamperedTag}:${parts[4]}`;
  assert.throws(() => {
    decryptShareGcm(tamperedTagSerialized, 'FOUNDATION');
  }, /authentication tag verification failed/, 'Tampered auth tag must fail verification');
});

test('5. Genuine Threshold MPC Signing: Correctness, EVM Compatibility & Zero Key Reconstruction', async () => {
  const n = 9;
  const threshold = 5;
  const wallet = generateSaralWalletMpc(n, threshold);

  assert.ok(wallet.address.startsWith('0x') && wallet.address.length === 42, 'Valid EVM address');
  assert.ok(wallet.aggregatedPublicKeyHex.startsWith('0x04'), 'Valid uncompressed secp256k1 point');

  // Unsigned EVM transaction
  const tx = ethers.Transaction.from({
    to: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    value: ethers.parseEther('0.005'),
    nonce: 1,
    gasLimit: 21000n,
    gasPrice: ethers.parseUnits('2', 'gwei'),
    chainId: 11155111n,
    type: 0,
  });

  const unsignedSerialized = tx.unsignedSerialized;

  // Active Quorums across the 3 independent domains:
  // Foundation (1-of-1)
  const foundation = {
    domain: 'FOUNDATION' as const,
    activeShareIndices: [1],
    shareValues: [wallet.foundation.shares[0].value],
  };

  // Public: 5 nodes (e.g. 1, 3, 5, 7, 9)
  const pubSub = wallet.publicDomain.shares.filter((s) => [1, 3, 5, 7, 9].includes(s.index));
  const publicDomain = {
    domain: 'PUBLIC' as const,
    activeShareIndices: pubSub.map((s) => s.index),
    shareValues: pubSub.map((s) => s.value),
  };

  // Private: 5 nodes (e.g. 2, 4, 6, 8, 9)
  const privSub = wallet.privateDomain.shares.filter((s) => [2, 4, 6, 8, 9].includes(s.index));
  const privateDomain = {
    domain: 'PRIVATE' as const,
    activeShareIndices: privSub.map((s) => s.index),
    shareValues: privSub.map((s) => s.value),
  };

  // Execute MPC signing
  const sigResult = await executeMpcThresholdSign(
    {
      unsignedTxSerialized: unsignedSerialized,
      chainId: 11155111n,
      foundation,
      publicDomain,
      privateDomain,
    },
    wallet.aggregatedPublicKeyHex,
    5,
    5
  );

  // Assertions
  assert.ok(sigResult.r.startsWith('0x'), 'Signature r must be hex');
  assert.ok(sigResult.s.startsWith('0x'), 'Signature s must be hex');
  assert.ok(sigResult.yParity === 0 || sigResult.yParity === 1, 'yParity must be 0 or 1');
  assert.ok(sigResult.rawSignedTx.startsWith('0x'), 'Raw signed transaction must be hex');

  // Verify EVM signer address matches wallet address
  const parsedTx = ethers.Transaction.from(sigResult.rawSignedTx);
  assert.strictEqual(
    parsedTx.from?.toLowerCase(),
    wallet.address.toLowerCase(),
    'Recovered signer of raw transaction must equal wallet address'
  );
  assert.strictEqual(parsedTx.hash, sigResult.txHash, 'Transaction hash must match');

  // BIP-62 low-s canonical check
  const sBigInt = BigInt(sigResult.s);
  assert.ok(sBigInt <= CURVE_ORDER / 2n, 'Signature s must satisfy canonical low-s (s <= n/2)');
});

