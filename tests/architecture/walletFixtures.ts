import { vi } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { saralBackendClient } from '../../apps/auth-server/src/clients/saralBackendClient';
import { WalletDomain, walletCommittee, walletCommitteeNodes, walletDomains } from '../../apps/auth-server/src/config/wallet';

export const SECP256K1_TEST_PUBKEY =
  '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';
export const ED25519_TEST_PUBKEY = '58' + '66'.repeat(31);

export const MESH_TEST_PUBLIC_KEYS = {
  mst: Buffer.from(secp256k1.Point.BASE.multiply(6n).toBytes(false)).toString('hex'),
  solana: Buffer.from(ed25519.Point.BASE.multiply(6n).toBytes()).toString('hex'),
  bitcoin: Buffer.from(secp256k1.Point.BASE.multiply(15n).toBytes(false)).toString('hex'),
};

export function mockWalletCoordinator() {
  const committee = (domain: WalletDomain) => ({
    committeeId: walletCommittee(domain),
    committee: walletCommitteeNodes(domain),
    n: 5, k: 3, t: 1, state: 'COMPLETED',
  });
  const start = vi.spyOn(saralBackendClient, 'startDkg').mockImplementation(async ({ sessionId } = {}, domain = 'foundation') => ({
    ...committee(domain), sessionId: sessionId!, success: true,
  }));
  vi.spyOn(saralBackendClient, 'getDkgStatus').mockImplementation(async (sessionId, domain = 'foundation') => ({
    ...committee(domain), sessionId, epoch: 1, completedNodes: 5, totalNodes: 5,
  }));
  const derive = vi.spyOn(saralBackendClient, 'derivePublicKey').mockImplementation(async (params, domain = 'foundation') => {
    const scalar = BigInt(walletDomains.indexOf(domain) + (params.chainFamily === 'bitcoin' ? 4 : 1));
    const point = params.curve === 'ed25519'
      ? ed25519.Point.BASE.multiply(scalar).toBytes()
      : secp256k1.Point.BASE.multiply(scalar).toBytes(false);
    return {
    success: true,
    walletId: params.walletId,
    keyId: params.keyId!,
    sessionId: params.dkgSessionId!,
    committeeId: walletCommittee(domain),
    epoch: 1,
    curve: params.curve!,
    threshold: 3,
    masterPublicKey: Buffer.from(point).toString('hex'),
    };
  });
  return { start, derive };
}
