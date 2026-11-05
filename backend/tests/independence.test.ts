/**
 * independence.test.ts
 *
 * Independence Enforcement & Sybil Resistance Test Suite.
 *
 * Patent & Specification Mandates (Claim 5, Paragraph [0022]):
 *   1. Sybil resistance: Identity attestation + Proof of Possession (PoP) signature per node.
 *   2. Membership exclusion: One operator cannot hold nodes in two domains.
 *   3. Jurisdiction & infrastructure diversity: Reject placement if too many nodes share a country or cloud provider (>33%).
 *   4. Replay attack rejection: PoP challenge freshness and reuse detection.
 *   5. Identity key pinning: Unauthorized public key substitution rejected.
 */

import test from 'node:test';
import assert from 'node:assert';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

process.env.NODE_ENV = 'test';

// Remove any test registry file
const testRegistryFile = path.resolve(process.cwd(), '.saral_registry', 'test_independence_registry.json');
if (fs.existsSync(testRegistryFile)) {
  try { fs.unlinkSync(testRegistryFile); } catch {}
}

import {
  ParticipantRegistry,
  computePoPChallenge,
} from '../src/participant/participantRegistry';

import {
  validatePlacementDiversity,
  computeWalletPlacement,
  NodeDiversityAttributes,
} from '../src/topology/placement';

import {
  buildClusterTopology,
} from '../src/topology/allocation';

import {
  randomScalar,
  scalarMultiplyG,
  scalarToHex,
} from '../src/crypto/secp256k1Math';

import { secp256k1 } from '@noble/curves/secp256k1';

function createNodeIdentity(nodeId: string, domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE', endpoint?: string) {
  const priv = randomScalar();
  const pubPoint = scalarMultiplyG(priv);
  const pubHex = pubPoint.toHex(true);
  const ep = endpoint || `ipc:///tmp/${nodeId}.sock`;
  const popTs = Date.now();
  const challenge = computePoPChallenge(nodeId, domain, ep, popTs);
  const hash = crypto.createHash('sha256').update(challenge).digest();
  const sig = secp256k1.sign(hash, scalarToHex(priv));
  const popSigHex = sig.toCompactHex();

  return {
    nodeId,
    domain,
    identityPublicKeyHex: pubHex,
    endpoint: ep,
    popTimestamp: popTs,
    proofOfPossessionSigHex: popSigHex,
  };
}

test('1. Sybil Resistance: Proof of Possession (PoP) Enforcement', () => {
  const registry = new ParticipantRegistry(testRegistryFile);
  registry.clear();

  const node = createNodeIdentity('pub-node-pop-01', 'PUBLIC');

  // Enrolling without PoP must fail
  assert.throws(
    () =>
      registry.enrollParticipant({
        nodeId: node.nodeId,
        domain: node.domain,
        nodeIndex: 1,
        shareIndex: 1,
        identityPublicKeyHex: node.identityPublicKeyHex,
        endpoint: node.endpoint,
        // No PoP
      }),
    /Proof of Possession \(PoP\) signature is mandatory/i
  );

  // Enrolling with forged / invalid PoP must fail
  const forgedSig = 'a'.repeat(128);
  assert.throws(
    () =>
      registry.enrollParticipant({
        nodeId: node.nodeId,
        domain: node.domain,
        nodeIndex: 1,
        shareIndex: 1,
        identityPublicKeyHex: node.identityPublicKeyHex,
        endpoint: node.endpoint,
        proofOfPossessionSigHex: forgedSig,
        popTimestamp: node.popTimestamp,
      }),
    /Proof of Possession verification failed/i
  );

  // Enrolling with valid PoP succeeds
  const enrolled = registry.enrollParticipant({
    nodeId: node.nodeId,
    domain: node.domain,
    nodeIndex: 1,
    shareIndex: 1,
    identityPublicKeyHex: node.identityPublicKeyHex,
    endpoint: node.endpoint,
    proofOfPossessionSigHex: node.proofOfPossessionSigHex,
    popTimestamp: node.popTimestamp,
    approved: true,
  });

  assert.strictEqual(enrolled.nodeId, 'pub-node-pop-01');
  assert.strictEqual(enrolled.identityPublicKeyHex, node.identityPublicKeyHex);
});

test('2. Membership Exclusion: One Operator Cannot Hold Nodes in Two Domains', () => {
  const registry = new ParticipantRegistry(testRegistryFile);
  registry.clear();

  const operatorId = 'operator-acme-corp';

  // 1. Enroll Foundation node under operator-acme-corp
  const fNode = createNodeIdentity('found-node-01', 'FOUNDATION');
  registry.enrollParticipant({
    nodeId: fNode.nodeId,
    domain: fNode.domain,
    nodeIndex: 1,
    shareIndex: 1,
    identityPublicKeyHex: fNode.identityPublicKeyHex,
    endpoint: fNode.endpoint,
    proofOfPossessionSigHex: fNode.proofOfPossessionSigHex,
    popTimestamp: fNode.popTimestamp,
    operator: { operatorId, organizationName: 'Acme Foundation' },
    approved: true,
  });

  // 2. Attempt to enroll a Public validator node under the same operator
  const pNode = createNodeIdentity('pub-node-01', 'PUBLIC');
  assert.throws(
    () =>
      registry.enrollParticipant({
        nodeId: pNode.nodeId,
        domain: pNode.domain,
        nodeIndex: 1,
        shareIndex: 1,
        identityPublicKeyHex: pNode.identityPublicKeyHex,
        endpoint: pNode.endpoint,
        proofOfPossessionSigHex: pNode.proofOfPossessionSigHex,
        popTimestamp: pNode.popTimestamp,
        operator: { operatorId, organizationName: 'Acme Validator' },
        approved: true,
      }),
    /Cross-Domain Membership Exclusion Violation/i,
    'Operator holding a Foundation node must be barred from Public domain'
  );
});

test('3. Replay Attack Resistance: PoP Signature Cannot Be Replayed', () => {
  const registry = new ParticipantRegistry(testRegistryFile);
  registry.clear();

  const node1 = createNodeIdentity('pub-node-rep-01', 'PUBLIC');
  registry.enrollParticipant({
    nodeId: node1.nodeId,
    domain: node1.domain,
    nodeIndex: 1,
    shareIndex: 1,
    identityPublicKeyHex: node1.identityPublicKeyHex,
    endpoint: node1.endpoint,
    proofOfPossessionSigHex: node1.proofOfPossessionSigHex,
    popTimestamp: node1.popTimestamp,
    approved: true,
  });

  // Attacker attempts to replay node1's PoP signature for node2
  assert.throws(
    () =>
      registry.enrollParticipant({
        nodeId: 'pub-node-rep-02',
        domain: 'PUBLIC',
        nodeIndex: 2,
        shareIndex: 2,
        identityPublicKeyHex: node1.identityPublicKeyHex,
        endpoint: 'ipc:///tmp/pub-node-rep-02.sock',
        proofOfPossessionSigHex: node1.proofOfPossessionSigHex,
        popTimestamp: node1.popTimestamp,
      }),
    /Replay attack detected/i
  );
});

test('4. Identity Key Pinning: Unauthorized Key Substitution Rejected', () => {
  const registry = new ParticipantRegistry(testRegistryFile);
  registry.clear();

  const node = createNodeIdentity('pub-node-pin-01', 'PUBLIC');
  registry.enrollParticipant({
    nodeId: node.nodeId,
    domain: node.domain,
    nodeIndex: 1,
    shareIndex: 1,
    identityPublicKeyHex: node.identityPublicKeyHex,
    endpoint: node.endpoint,
    proofOfPossessionSigHex: node.proofOfPossessionSigHex,
    popTimestamp: node.popTimestamp,
    approved: true,
  });

  // Verify authentic identity
  const verifyValid = registry.verifyEnrolledIdentity(
    node.nodeId,
    node.identityPublicKeyHex,
    'PUBLIC',
    node.endpoint
  );
  assert.strictEqual(verifyValid.valid, true);

  // Substitute with a malicious public key
  const roguePriv = randomScalar();
  const roguePub = scalarMultiplyG(roguePriv).toHex(true);

  const verifySubstituted = registry.verifyEnrolledIdentity(
    node.nodeId,
    roguePub,
    'PUBLIC',
    node.endpoint
  );
  assert.strictEqual(verifySubstituted.valid, false);
  assert.ok(verifySubstituted.reason?.includes('Public key substitution detected'));
});

test('5. Infrastructure & Jurisdiction Diversity Enforcement (Patent Claim 5)', () => {
  const topology = buildClusterTopology(19); // 7 Foundation, 6 Public, 6 Private
  const placement = computeWalletPlacement('wallet-diversity-test-01', topology, 1);

  // Case A: Excessive concentration on AWS us-east-1 (> 33% of domain)
  // Public domain has 6 nodes. 3 nodes (> 6 * 0.34 = 2.04) on AWS us-east-1
  const concentratedMetadata: Record<string, NodeDiversityAttributes> = {};
  for (const nodeId of topology.foundation.nodeIds) {
    concentratedMetadata[nodeId] = {
      nodeId,
      operatorId: `op-${nodeId}`,
      jurisdiction: 'CH',
      hostingProvider: 'BareMetal-Swiss',
    };
  }
  for (let i = 0; i < topology.public.nodeIds.length; i++) {
    const nodeId = topology.public.nodeIds[i];
    concentratedMetadata[nodeId] = {
      nodeId,
      operatorId: `op-pub-${i}`,
      jurisdiction: i < 4 ? 'US' : 'DE', // 4 out of 6 nodes in US (> 33%)
      hostingProvider: i < 4 ? 'AWS' : 'Hetzner', // 4 out of 6 on AWS (> 33%)
    };
  }
  for (const nodeId of topology.private.nodeIds) {
    concentratedMetadata[nodeId] = {
      nodeId,
      operatorId: `op-${nodeId}`,
      jurisdiction: 'Local',
      hostingProvider: 'UserDevice',
    };
  }

  const checkFail = validatePlacementDiversity(placement, concentratedMetadata, 0.34);
  assert.strictEqual(checkFail.valid, false);
  assert.ok(checkFail.violations.some((v) => v.includes('Jurisdiction concentration violation')));
  assert.ok(checkFail.violations.some((v) => v.includes('Hosting provider concentration violation')));

  // Case B: Balanced & Diverse Infrastructure (max 2 nodes per provider/jurisdiction)
  const balancedMetadata: Record<string, NodeDiversityAttributes> = {};
  for (let i = 0; i < topology.foundation.nodeIds.length; i++) {
    const nodeId = topology.foundation.nodeIds[i];
    const countries = ['CH', 'SE', 'IS', 'SG', 'NO', 'FI', 'AT'];
    balancedMetadata[nodeId] = {
      nodeId,
      operatorId: `op-f-${i}`,
      jurisdiction: countries[i % countries.length],
      hostingProvider: `Provider-F-${i % 4}`,
    };
  }
  for (let i = 0; i < topology.public.nodeIds.length; i++) {
    const nodeId = topology.public.nodeIds[i];
    const countries = ['DE', 'JP', 'CA', 'AU', 'NL', 'SG'];
    const providers = ['Hetzner', 'OVH', 'Equinix', 'GCP', 'DigitalOcean', 'Vultr'];
    balancedMetadata[nodeId] = {
      nodeId,
      operatorId: `op-p-${i}`,
      jurisdiction: countries[i % countries.length],
      hostingProvider: providers[i % providers.length],
    };
  }
  for (let i = 0; i < topology.private.nodeIds.length; i++) {
    const nodeId = topology.private.nodeIds[i];
    balancedMetadata[nodeId] = {
      nodeId,
      operatorId: `op-u-${i}`,
      jurisdiction: `UserLocation-${i}`,
      hostingProvider: `UserPlatform-${i}`,
    };
  }

  const checkPass = validatePlacementDiversity(placement, balancedMetadata, 0.34);
  assert.strictEqual(checkPass.valid, true);
  assert.strictEqual(checkPass.violations.length, 0);
});
