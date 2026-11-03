import test from 'node:test';
import assert from 'node:assert';
import { ethers } from 'ethers';
import { nodeCluster, buildNodeName } from '../src/services/nodeClusterService';
import { calculateDistanceKm, getCurrentTimeInTimezone } from '../src/services/locationService';
import { generateSaralWalletMpc, executeMpcThresholdSign } from '../src/crypto/thresholdEcdsa';
import { encryptShareGcm, decryptShareGcm } from '../src/crypto/secureEncryption';

test('1. 27-Node Cluster: Multi-Domain Deployment & Batch Retrieval', async () => {
  const userId = 'user-node-cluster-test-01';

  // Deploy 9 Foundation, 9 Public, and 9 Private shares
  for (let i = 1; i <= 9; i++) {
    const encF = encryptShareGcm(`foundation-share-data-${i}`, 'FOUNDATION');
    await nodeCluster.deployShareToNode(userId, 'FOUNDATION', i, encF.serialized);

    const encP = encryptShareGcm(`public-share-data-${i}`, 'PUBLIC');
    await nodeCluster.deployShareToNode(userId, 'PUBLIC', i, encP.serialized);

    const encU = encryptShareGcm(`private-share-data-${i}`, 'PRIVATE');
    await nodeCluster.deployShareToNode(userId, 'PRIVATE', i, encU.serialized);
  }

  // Retrieve batch of threshold nodes (e.g. 5 nodes per domain)
  const queryNodes = [
    { userId, domain: 'FOUNDATION' as const, nodeIndex: 1, containerName: buildNodeName(userId, 'FOUNDATION', 1) },
    ...[1, 2, 3, 4, 5].map((idx) => ({
      userId,
      domain: 'PUBLIC' as const,
      nodeIndex: idx,
      containerName: buildNodeName(userId, 'PUBLIC', idx),
    })),
    ...[2, 4, 6, 8, 9].map((idx) => ({
      userId,
      domain: 'PRIVATE' as const,
      nodeIndex: idx,
      containerName: buildNodeName(userId, 'PRIVATE', idx),
    })),
  ];

  const batchResults = await nodeCluster.retrieveSharesBatch(queryNodes);
  assert.strictEqual(batchResults.size, 11);

  // Verify decrypted contents match
  const fShare = batchResults.get(buildNodeName(userId, 'FOUNDATION', 1));
  assert.ok(fShare);
  assert.strictEqual(decryptShareGcm(fShare, 'FOUNDATION'), 'foundation-share-data-1');

  // Verify health check
  const clusterStatus = await nodeCluster.checkClusterHealth(userId, 5);
  assert.strictEqual(clusterStatus.totalNodes, 27);
  assert.strictEqual(clusterStatus.healthy, true);
  assert.strictEqual(clusterStatus.domainBreakdown.FOUNDATION.online, 9);
  assert.strictEqual(clusterStatus.domainBreakdown.PUBLIC.online, 9);
  assert.strictEqual(clusterStatus.domainBreakdown.PRIVATE.online, 9);
});

test('2. Zero-Trust Policy Math: Haversine Geofencing & Timezone Calculations', () => {
  // Indore coordinates: 22.7196, 75.8577
  // Point within 5 km: 22.7300, 75.8600
  const d1 = calculateDistanceKm(22.7196, 75.8577, 22.7300, 75.8600);
  assert.ok(d1 < 5.0, `Distance should be < 5 km, got ${d1}`);

  // Point outside 25 km (e.g. Ujjain ~50 km away: 23.1765, 75.7885)
  const d2 = calculateDistanceKm(22.7196, 75.8577, 23.1765, 75.7885);
  assert.ok(d2 > 40.0 && d2 < 60.0, `Distance should be ~50 km, got ${d2}`);

  // Timezone calculation
  const timeInfo = getCurrentTimeInTimezone('Asia/Kolkata');
  assert.ok(timeInfo.hour >= 0 && timeInfo.hour <= 23);
  assert.ok(timeInfo.minute >= 0 && timeInfo.minute <= 59);
  assert.match(timeInfo.timeStr, /^\d{2}:\d{2}$/);
});

test('3. End-to-End Flow: Generation -> Threshold MPC Signing -> Broadcastable EVM Tx', async () => {
  // 1. Generation
  const wallet = generateSaralWalletMpc(9, 5);
  assert.ok(wallet.address);

  // 2. Unsigned transaction
  const unsignedTx = ethers.Transaction.from({
    to: '0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    value: ethers.parseEther('0.001'),
    gasPrice: ethers.parseUnits('1', 'gwei'),
    gasLimit: 21000n,
    nonce: 0,
    chainId: 11155111n,
    type: 0,
  }).unsignedSerialized;

  // 3. Threshold quorums
  const foundation = {
    domain: 'FOUNDATION' as const,
    activeShareIndices: [1],
    shareValues: [wallet.foundation.shares[0].value],
  };
  const publicDomain = {
    domain: 'PUBLIC' as const,
    activeShareIndices: [1, 2, 3, 4, 5],
    shareValues: wallet.publicDomain.shares.slice(0, 5).map((s) => s.value),
  };
  const privateDomain = {
    domain: 'PRIVATE' as const,
    activeShareIndices: [1, 3, 5, 7, 9],
    shareValues: wallet.privateDomain.shares.filter((s) => [1, 3, 5, 7, 9].includes(s.index)).map((s) => s.value),
  };

  // 4. MPC Signing
  const sig = await executeMpcThresholdSign(
    {
      unsignedTxSerialized: unsignedTx,
      chainId: 11155111n,
      foundation,
      publicDomain,
      privateDomain,
    },
    wallet.aggregatedPublicKeyHex,
    5,
    5
  );

  // 5. Verification
  assert.ok(sig.rawSignedTx);
  assert.ok(sig.txHash);
  const recovered = ethers.recoverAddress(ethers.keccak256(unsignedTx), {
    r: sig.r,
    s: sig.s,
    yParity: sig.yParity,
  });
  assert.strictEqual(recovered.toLowerCase(), wallet.address.toLowerCase());
});

