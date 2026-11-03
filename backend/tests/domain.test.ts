import test from 'node:test';
import assert from 'node:assert';
import { ethers } from 'ethers';
import {
  generateSaralWalletMpc,
  executeMpcThresholdSign,
  verifyThreeDomainQuorum,
} from '../src/crypto/thresholdEcdsa';

test('1. Separation of Powers: Single-domain quorums strictly fail', async () => {
  const wallet = generateSaralWalletMpc(9, 5);
  const dummyTx = ethers.Transaction.from({
    to: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    value: 1000n,
    nonce: 0,
    gasLimit: 21000n,
    gasPrice: 1000000000n,
    chainId: 11155111n,
    type: 0,
  }).unsignedSerialized;

  // A. Foundation-only fails (Public & Private missing)
  await assert.rejects(async () => {
    await executeMpcThresholdSign(
      {
        unsignedTxSerialized: dummyTx,
        chainId: 11155111n,
        foundation: {
          domain: 'FOUNDATION',
          activeShareIndices: [1],
          shareValues: [wallet.foundation.shares[0].value],
        },
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: [],
          shareValues: [],
        },
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: [],
          shareValues: [],
        },
      },
      wallet.aggregatedPublicKeyHex,
      5,
      5
    );
  }, /Public domain threshold not met/);

  // B. Public-only fails (Foundation & Private missing)
  await assert.rejects(async () => {
    await executeMpcThresholdSign(
      {
        unsignedTxSerialized: dummyTx,
        chainId: 11155111n,
        foundation: {
          domain: 'FOUNDATION',
          activeShareIndices: [],
          shareValues: [],
        },
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: [1, 2, 3, 4, 5],
          shareValues: wallet.publicDomain.shares.slice(0, 5).map((s) => s.value),
        },
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: [],
          shareValues: [],
        },
      },
      wallet.aggregatedPublicKeyHex,
      5,
      5
    );
  }, /Foundation domain participation is required/);

  // C. Private-only fails (Foundation & Public missing)
  await assert.rejects(async () => {
    await executeMpcThresholdSign(
      {
        unsignedTxSerialized: dummyTx,
        chainId: 11155111n,
        foundation: {
          domain: 'FOUNDATION',
          activeShareIndices: [],
          shareValues: [],
        },
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: [],
          shareValues: [],
        },
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: [1, 2, 3, 4, 5],
          shareValues: wallet.privateDomain.shares.slice(0, 5).map((s) => s.value),
        },
      },
      wallet.aggregatedPublicKeyHex,
      5,
      5
    );
  }, /Foundation domain participation is required/);
});

test('2. Separation of Powers: Two-domain coalitions strictly fail', async () => {
  const wallet = generateSaralWalletMpc(9, 5);
  const dummyTx = ethers.Transaction.from({
    to: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    value: 1000n,
    nonce: 0,
    gasLimit: 21000n,
    gasPrice: 1000000000n,
    chainId: 11155111n,
    type: 0,
  }).unsignedSerialized;

  // Coalition 1: Foundation + Public (Private missing - malicious custodian attack)
  await assert.rejects(async () => {
    await executeMpcThresholdSign(
      {
        unsignedTxSerialized: dummyTx,
        chainId: 11155111n,
        foundation: {
          domain: 'FOUNDATION',
          activeShareIndices: [1],
          shareValues: [wallet.foundation.shares[0].value],
        },
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: [1, 2, 3, 4, 5],
          shareValues: wallet.publicDomain.shares.slice(0, 5).map((s) => s.value),
        },
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: [],
          shareValues: [],
        },
      },
      wallet.aggregatedPublicKeyHex,
      5,
      5
    );
  }, /Private domain threshold not met/);

  // Coalition 2: Foundation + Private (Public missing)
  await assert.rejects(async () => {
    await executeMpcThresholdSign(
      {
        unsignedTxSerialized: dummyTx,
        chainId: 11155111n,
        foundation: {
          domain: 'FOUNDATION',
          activeShareIndices: [1],
          shareValues: [wallet.foundation.shares[0].value],
        },
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: [],
          shareValues: [],
        },
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: [1, 2, 3, 4, 5],
          shareValues: wallet.privateDomain.shares.slice(0, 5).map((s) => s.value),
        },
      },
      wallet.aggregatedPublicKeyHex,
      5,
      5
    );
  }, /Public domain threshold not met/);

  // Coalition 3: Public + Private (Foundation institutional veto missing)
  await assert.rejects(async () => {
    await executeMpcThresholdSign(
      {
        unsignedTxSerialized: dummyTx,
        chainId: 11155111n,
        foundation: {
          domain: 'FOUNDATION',
          activeShareIndices: [],
          shareValues: [],
        },
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: [1, 2, 3, 4, 5],
          shareValues: wallet.publicDomain.shares.slice(0, 5).map((s) => s.value),
        },
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: [1, 2, 3, 4, 5],
          shareValues: wallet.privateDomain.shares.slice(0, 5).map((s) => s.value),
        },
      },
      wallet.aggregatedPublicKeyHex,
      5,
      5
    );
  }, /Foundation domain participation is required/);
});

test('3. Domain Internal Quorums: Shortfall in Public or Private nodes fails', async () => {
  const wallet = generateSaralWalletMpc(9, 5);
  const dummyTx = ethers.Transaction.from({
    to: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    value: 1000n,
    nonce: 0,
    gasLimit: 21000n,
    gasPrice: 1000000000n,
    chainId: 11155111n,
    type: 0,
  }).unsignedSerialized;

  // Only 4 Public nodes (threshold is 5)
  await assert.rejects(async () => {
    await executeMpcThresholdSign(
      {
        unsignedTxSerialized: dummyTx,
        chainId: 11155111n,
        foundation: {
          domain: 'FOUNDATION',
          activeShareIndices: [1],
          shareValues: [wallet.foundation.shares[0].value],
        },
        publicDomain: {
          domain: 'PUBLIC',
          activeShareIndices: [1, 2, 3, 4],
          shareValues: wallet.publicDomain.shares.slice(0, 4).map((s) => s.value),
        },
        privateDomain: {
          domain: 'PRIVATE',
          activeShareIndices: [1, 2, 3, 4, 5],
          shareValues: wallet.privateDomain.shares.slice(0, 5).map((s) => s.value),
        },
      },
      wallet.aggregatedPublicKeyHex,
      5,
      5
    );
  }, /Public domain threshold not met: require >= 5 nodes, got 4/);
});

test('4. All Three Valid Domain Quorums Succeed with Byzantine Node Fault Tolerance', async () => {
  const wallet = generateSaralWalletMpc(9, 5);
  const dummyTx = ethers.Transaction.from({
    to: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    value: ethers.parseEther('0.01'),
    nonce: 0,
    gasLimit: 21000n,
    gasPrice: 1000000000n,
    chainId: 11155111n,
    type: 0,
  }).unsignedSerialized;

  // Scenario: 4 Public nodes offline (nodes 6, 7, 8, 9 crashed)
  // Active nodes: 1, 2, 3, 4, 5 (quorum met)
  // Scenario: 4 Private nodes offline (devices 1, 3, 5, 7 offline)
  // Active nodes: 2, 4, 6, 8, 9 (quorum met)
  const result = await executeMpcThresholdSign(
    {
      unsignedTxSerialized: dummyTx,
      chainId: 11155111n,
      foundation: {
        domain: 'FOUNDATION',
        activeShareIndices: [1],
        shareValues: [wallet.foundation.shares[0].value],
      },
      publicDomain: {
        domain: 'PUBLIC',
        activeShareIndices: [1, 2, 3, 4, 5],
        shareValues: wallet.publicDomain.shares.filter((s) => [1, 2, 3, 4, 5].includes(s.index)).map((s) => s.value),
      },
      privateDomain: {
        domain: 'PRIVATE',
        activeShareIndices: [2, 4, 6, 8, 9],
        shareValues: wallet.privateDomain.shares.filter((s) => [2, 4, 6, 8, 9].includes(s.index)).map((s) => s.value),
      },
    },
    wallet.aggregatedPublicKeyHex,
    5,
    5
  );

  assert.ok(result.rawSignedTx);
  const parsed = ethers.Transaction.from(result.rawSignedTx);
  assert.strictEqual(parsed.from?.toLowerCase(), wallet.address.toLowerCase());
  assert.strictEqual(result.signingQuorum.foundationAuthorized, true);
  assert.strictEqual(result.signingQuorum.publicNodeCount, 5);
  assert.strictEqual(result.signingQuorum.privateNodeCount, 5);
});

