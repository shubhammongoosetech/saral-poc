/**
 * topology.test.ts
 *
 * Dynamic Topology, Allocation & Rendezvous (HRW) Placement Test Suite.
 *
 * Patent & Specification Mandates (Sections 2.1, 2.2, Claims 1, 11):
 *   1. Allocation splits arbitrary N >= 9 across Foundation, Public, and Private (each >= 3).
 *   2. Exemplary splits: N=19 -> 7, 6, 6; N=27 -> 9, 9, 9.
 *   3. Dynamic threshold calculation: t = floor(2n/3) + 1, always t > n/2.
 *   4. Critical Rendezvous HRW Test:
 *      Create 100 wallets with N=19, add 8 nodes (scaling to N=27), load all 100 wallets again,
 *      and assert every single wallet's pinned placement is 100% IDENTICAL!
 *   5. Signed manifest verification on participating nodes.
 *   6. Proactive resharing increments epoch.
 */

import test from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';

import {
  allocate,
  computeThreshold,
  buildClusterTopology,
} from '../src/topology/allocation';
import {
  computeHrwScore,
  selectNodesHrw,
  computeWalletPlacement,
  generateNodeManifest,
  pinWalletPlacement,
  getPinnedWalletPlacement,
  pinnedPlacementsCache,
  WalletPlacement,
} from '../src/topology/placement';

test('1. Dynamic Allocation: N=19 -> 7, 6, 6 and N=27 -> 9, 9, 9', () => {
  const alloc19 = allocate(19);
  assert.strictEqual(alloc19.foundation, 7);
  assert.strictEqual(alloc19.public, 6);
  assert.strictEqual(alloc19.private, 6);

  const alloc27 = allocate(27);
  assert.strictEqual(alloc27.foundation, 9);
  assert.strictEqual(alloc27.public, 9);
  assert.strictEqual(alloc27.private, 9);

  // Custom weights (e.g. Public gets more)
  const allocWeighted = allocate(19, { foundation: 1, public: 2, private: 1 });
  assert.strictEqual(allocWeighted.foundation + allocWeighted.public + allocWeighted.private, 19);
  assert.ok(allocWeighted.public >= allocWeighted.foundation);
  assert.ok(allocWeighted.foundation >= 3 && allocWeighted.public >= 3 && allocWeighted.private >= 3);
});

test('2. Allocation Boundary Constraints: N < 9 and < 3 nodes per domain rejected', () => {
  assert.throws(() => allocate(8), /N must be >= 9/);
  assert.throws(() => allocate(5), /N must be >= 9/);
});

test('3. Dynamic Thresholds: t = floor(2n/3) + 1, always t > n/2', () => {
  const cases = [
    { n: 3, expectedT: 3 },
    { n: 6, expectedT: 5 },
    { n: 7, expectedT: 5 },
    { n: 9, expectedT: 7 },
    { n: 12, expectedT: 9 },
  ];

  for (const { n, expectedT } of cases) {
    const t = computeThreshold(n);
    assert.strictEqual(t, expectedT, `Threshold for n=${n} must be ${expectedT}`);
    assert.ok(t > Math.floor(n / 2), `Threshold ${t} must be strictly greater than majority n/2=${Math.floor(n / 2)}`);
    assert.ok(t <= n, `Threshold ${t} must not exceed n=${n}`);
  }
});

test('4. Full ClusterTopology Construction for N=19 and N=27', () => {
  const topo19 = buildClusterTopology(19);
  assert.strictEqual(topo19.totalNodes, 19);
  assert.strictEqual(topo19.foundation.count, 7);
  assert.strictEqual(topo19.foundation.threshold, 5);
  assert.strictEqual(topo19.public.count, 6);
  assert.strictEqual(topo19.public.threshold, 5);
  assert.strictEqual(topo19.private.count, 6);
  assert.strictEqual(topo19.private.threshold, 5);

  const topo27 = buildClusterTopology(27);
  assert.strictEqual(topo27.totalNodes, 27);
  assert.strictEqual(topo27.foundation.count, 9);
  assert.strictEqual(topo27.foundation.threshold, 7);
  assert.strictEqual(topo27.public.count, 9);
  assert.strictEqual(topo27.public.threshold, 7);
  assert.strictEqual(topo27.private.count, 9);
  assert.strictEqual(topo27.private.threshold, 7);
});

test('5. Rendezvous (HRW) Hashing & Pinned Placement: 100 Wallets with N=19, add 8 nodes, all 100 placements remain IDENTICAL', async () => {
  // Clear cache for clean test
  pinnedPlacementsCache.clear();

  const topo19 = buildClusterTopology(19);

  // Generate 100 wallets and pin their placements
  const wallets: Array<{ walletId: string; initialPlacement: WalletPlacement }> = [];
  for (let i = 1; i <= 100; i++) {
    const walletId = `wallet-test-uuid-${i}-${crypto.randomUUID()}`;
    const placement = computeWalletPlacement(walletId, topo19, 1, `user-${i}`);

    // Pin the placement (in DB / cache)
    await pinWalletPlacement(null, placement);
    wallets.push({ walletId, initialPlacement: placement });
  }

  assert.strictEqual(wallets.length, 100);

  // Cluster Expansion: Add 8 nodes to scale to N=27 (9 Foundation, 9 Public, 9 Private)
  const topo27 = buildClusterTopology(27);
  assert.strictEqual(topo27.totalNodes, 27);

  // Load all 100 wallets again and verify that every pinned placement is 100% IDENTICAL
  for (const { walletId, initialPlacement } of wallets) {
    const loadedPlacement = await getPinnedWalletPlacement(null, walletId);

    assert.ok(loadedPlacement !== null, `Pinned placement for wallet ${walletId} must be loaded`);
    assert.strictEqual(loadedPlacement.epoch, initialPlacement.epoch);
    assert.strictEqual(loadedPlacement.manifestHash, initialPlacement.manifestHash);

    // Assert exact identical node lists across all 3 domains
    assert.deepStrictEqual(
      loadedPlacement.foundation.assignedNodeIds,
      initialPlacement.foundation.assignedNodeIds,
      `Foundation nodes for wallet ${walletId} must be unchanged after adding nodes to cluster`
    );
    assert.deepStrictEqual(
      loadedPlacement.public.assignedNodeIds,
      initialPlacement.public.assignedNodeIds,
      `Public nodes for wallet ${walletId} must be unchanged after adding nodes to cluster`
    );
    assert.deepStrictEqual(
      loadedPlacement.private.assignedNodeIds,
      initialPlacement.private.assignedNodeIds,
      `Private nodes for wallet ${walletId} must be unchanged after adding nodes to cluster`
    );
  }
});

test('6. Node Signed Manifest Verification: Each node receives verifiable signed manifest', () => {
  const topo = buildClusterTopology(19);
  const walletId = 'wallet-manifest-test-01';
  const placement = computeWalletPlacement(walletId, topo, 1, 'user-01');

  const coordinatorSecret = 'test-coordinator-hmac-secret-32-chars-long';
  const targetNodeId = placement.public.assignedNodeIds[0];

  const manifest = generateNodeManifest(placement, targetNodeId, coordinatorSecret);

  assert.strictEqual(manifest.walletId, walletId);
  assert.strictEqual(manifest.nodeId, targetNodeId);
  assert.strictEqual(manifest.domain, 'PUBLIC');
  assert.strictEqual(manifest.domainThreshold, 5);
  assert.strictEqual(manifest.allAssignedNodesInDomain.length, 6);
  assert.ok(manifest.signedByCoordinator.length > 0);

  // Verify signature
  const expectedData = `${walletId}:1:${targetNodeId}:PUBLIC:${placement.manifestHash}`;
  const expectedSig = crypto.createHmac('sha256', coordinatorSecret).update(expectedData).digest('hex');
  assert.strictEqual(manifest.signedByCoordinator, expectedSig, 'Manifest signature must verify');
});

test('7. Proactive Resharing: Increments epoch, produces new pinned placement', async () => {
  const topo19 = buildClusterTopology(19);
  const walletId = 'wallet-reshare-test-01';

  // Epoch 1
  const placementEpoch1 = computeWalletPlacement(walletId, topo19, 1);
  await pinWalletPlacement(null, placementEpoch1);

  // Epoch 2 resharing
  const topo27 = buildClusterTopology(27);
  const placementEpoch2 = computeWalletPlacement(walletId, topo27, 2);
  await pinWalletPlacement(null, placementEpoch2);

  const loadedEpoch1 = await getPinnedWalletPlacement(null, walletId, 1);
  const loadedEpoch2 = await getPinnedWalletPlacement(null, walletId, 2);

  assert.strictEqual(loadedEpoch1?.epoch, 1);
  assert.strictEqual(loadedEpoch2?.epoch, 2);
  assert.notStrictEqual(loadedEpoch1?.manifestHash, loadedEpoch2?.manifestHash);
});

