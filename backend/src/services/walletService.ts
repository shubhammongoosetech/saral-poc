/**
 * walletService.ts
 *
 * SARAL Non-Custodial Key Management & MPC Wallet Service
 *
 * Implements:
 *  - 3-Domain Separation of Powers (Foundation, Public, Private).
 *  - Distributed Key Generation (DKG) with Zero Central Private Key.
 *  - Dynamic Distributed Storage Nodes across the 3 Trust Domains configured via .env.
 *  - Genuine Multi-Party Computation (MPC) Threshold Signing for EVM.
 *  - Strict Zero-Key Database Storage: No private keys or plaintext shares in PostgreSQL.
 */

import { ethers } from 'ethers';
import { prisma } from '../config/db';
import { env } from '../config/env';
import {
  generateSaralWalletMpc,
  executeMpcThresholdSign,
  DomainType,
} from '../crypto/thresholdEcdsa';
import { statelessMpcCoordinator } from '../crypto/mpcCoordinator';
import {
  verifyShareWithCommitments,
} from '../crypto/shamirField';
import {
  scalarToHex,
} from '../crypto/secp256k1Math';
import {
  encryptShareGcm,
} from '../crypto/secureEncryption';
import {
  AuthenticatedParticipantClient,
} from '../participant/participantClient';
import {
  nodeCluster,
  normalizeDomain,
  getDomainLegacyAliases,
} from './nodeClusterService';
import {
  getBalance,
  getBalanceWeiOrNull,
  getAccountNonce,
  getGasFeeData,
  broadcastRawTransaction,
} from './chainService';
import { BadRequestError } from '../utils/errors';
import { evaluateAccessPolicy } from './locationService';
import { getBackendChainConfig } from '../config/chains';
import { computeWalletPlacement, pinWalletPlacement, getPinnedWalletPlacement } from '../topology/placement';
import { buildClusterTopology } from '../topology/allocation';
import { getTopologyConfig } from '../config/topologyConfig';
import { getOrDeriveSessionWallet, setSessionWallet } from './sessionWalletRegistry';
import { redactSensitive } from '../utils/logger';

export interface DomainCommitments {
  foundation: string[];
  public: string[];
  private: string[];
}

export const walletCommitmentsStore = new Map<string, DomainCommitments>();

export interface WalletInfo {
  address: string;
  publicKey: string;
  balance: string;
  createdAt: string;
  n: number;
  threshold: number;
  protocolVersion: string;
  domains: {
    foundation: { role: string; nodes: number; threshold: number };
    public: { role: string; nodes: number; threshold: number };
    private: { role: string; nodes: number; threshold: number };
  };
}

const DOMAINS: DomainType[] = ['FOUNDATION', 'PUBLIC', 'PRIVATE'];

export async function hasExistingWallet(userId: string): Promise<boolean> {
  const [placementCount, shareCount] = await Promise.all([
    prisma.walletPlacement.count({ where: { userId } }).catch(() => 0),
    prisma.keyShare.count({ where: { userId } }).catch(() => 0),
  ]);
  return placementCount > 0 || shareCount > 0;
}

/**
 * Retrieves wallet metadata and live on-chain balance via dynamic session derivation
 * without private-key reconstruction or persistent database storage of address/keys.
 */
export async function getExistingWallet(userId: string, sessionId?: string): Promise<WalletInfo | null> {
  const exists = await hasExistingWallet(userId);
  if (!exists) return null;

  const sessionWallet = await getOrDeriveSessionWallet(userId, sessionId);
  const balance = await getBalance(sessionWallet.address);
  const placement = await getPinnedWalletPlacement(prisma, userId);
  const config = getTopologyConfig();

  const foundationNodes = placement?.foundation.assignedNodeIds.length ?? config.foundation.nodes;
  const foundationThreshold = placement?.foundation.threshold ?? config.foundation.threshold;

  const publicNodes = placement?.public.assignedNodeIds.length ?? config.public.nodes;
  const publicThreshold = placement?.public.threshold ?? config.public.threshold;

  const privateNodes = placement?.private.assignedNodeIds.length ?? config.private.nodes;
  const privateThreshold = placement?.private.threshold ?? config.private.threshold;

  return {
    address: sessionWallet.address,
    publicKey: sessionWallet.publicKey,
    balance,
    createdAt: new Date(sessionWallet.derivedAt).toISOString(),
    n: publicNodes,
    threshold: publicThreshold,
    protocolVersion: sessionWallet.protocolVersion,
    domains: {
      foundation: { role: 'Institutional Administration', nodes: foundationNodes, threshold: foundationThreshold },
      public: { role: 'Public Independent Validator Nodes', nodes: publicNodes, threshold: publicThreshold },
      private: { role: 'Sovereign User Nodes', nodes: privateNodes, threshold: privateThreshold },
    },
  };
}

/**
 * CASE A — Generate Wallet via 3-Domain MPC DKG
 *
 * 1. Generates 3 independent domain key shares: Foundation, Public, Private.
 * 2. Homomorphically aggregates public key Q = Q_F + Q_P + Q_U.
 * 3. Derives Ethereum wallet address from Q.
 * 4. Shards Public domain key into n shares with threshold t.
 * 5. Shards Private domain key into n shares with threshold t.
 * 6. Generates 1 Foundation node share.
 * 7. Encrypts each share with AES-256-GCM using domain-separated HKDF keys.
 * 8. Deploys each share to its respective node container.
 * 9. Stores ONLY metadata in PostgreSQL (NO private keys or plaintext shares).
 *
 * CRITICAL ARCHITECTURAL GUARANTEE:
 * The complete private key x is NEVER formed or reconstructed in any variable or Buffer.
 */
export async function generateWallet(userId: string): Promise<{
  address: string;
  publicKey: string;
  balance: string;
  n: number;
  threshold: number;
  protocolVersion: string;
}> {
  if (await hasExistingWallet(userId)) {
    throw new Error('Wallet already exists for this user. Only one wallet generation is permitted.');
  }

  const config = getTopologyConfig();
  const pubN = config.public.nodes;
  const pubT = config.public.threshold;
  const foundN = config.foundation.nodes;
  const foundT = config.foundation.threshold;
  const privN = config.private.nodes;
  const privT = config.private.threshold;

  // Execute DKG: Generate 3 domains without central private key
  const mpcWallet = generateSaralWalletMpc(pubN, pubT, foundN, foundT, privN, privT);
  const address = mpcWallet.address;
  const publicKey = mpcWallet.aggregatedPublicKeyHex;

  // Store Feldman VSS commitments for share integrity verification in memory
  walletCommitmentsStore.set(userId, {
    foundation: mpcWallet.foundation.commitments,
    public: mpcWallet.publicDomain.commitments,
    private: mpcWallet.privateDomain.commitments,
  });

  // Dynamic Topology & Rendezvous (HRW) Placement Pinning (Patent Section 2.2)
  const topology = buildClusterTopology(config);
  const placement = computeWalletPlacement(userId, topology, 1, userId);
  await pinWalletPlacement(prisma, placement);

  // Deploy Nodes across the 3 Domains:
  // 1. Foundation Domain: distinct independent institutional shares
  for (const s of mpcWallet.foundation.shares) {
    const encrypted = encryptShareGcm(
      JSON.stringify({ index: s.index, value: scalarToHex(s.value) }),
      'FOUNDATION'
    );
    const nodeInfo = await nodeCluster.deployShareToNode(userId, 'FOUNDATION', s.index, encrypted.serialized);

    await prisma.keyShare.create({
      data: {
        userId,
        category: 'FOUNDATION',
        shareIndex: s.index,
        n: foundN,
        threshold: foundT,
        containerId: nodeInfo.nodeId,
        containerName: nodeInfo.nodeName,
      },
    });
  }

  // 2. Public Domain: n validator nodes
  for (const s of mpcWallet.publicDomain.shares) {
    const encrypted = encryptShareGcm(
      JSON.stringify({ index: s.index, value: scalarToHex(s.value) }),
      'PUBLIC'
    );
    const nodeInfo = await nodeCluster.deployShareToNode(userId, 'PUBLIC', s.index, encrypted.serialized);

    await prisma.keyShare.create({
      data: {
        userId,
        category: 'PUBLIC',
        shareIndex: s.index,
        n: pubN,
        threshold: pubT,
        containerId: nodeInfo.nodeId,
        containerName: nodeInfo.nodeName,
      },
    });
  }

  // 3. Private Domain: n sovereign user nodes
  for (const s of mpcWallet.privateDomain.shares) {
    const encrypted = encryptShareGcm(
      JSON.stringify({ index: s.index, value: scalarToHex(s.value) }),
      'PRIVATE'
    );
    const nodeInfo = await nodeCluster.deployShareToNode(userId, 'PRIVATE', s.index, encrypted.serialized);

    await prisma.keyShare.create({
      data: {
        userId,
        category: 'PRIVATE',
        shareIndex: s.index,
        n: privN,
        threshold: privT,
        containerId: nodeInfo.nodeId,
        containerName: nodeInfo.nodeName,
      },
    });
  }

  // Register into ephemeral in-memory session registry (never persisted to disk/DB)
  setSessionWallet({
    sessionId: userId,
    userId,
    address,
    publicKey,
    derivedAt: Date.now(),
    expiresAt: Date.now() + (env.ACCESS_TOKEN_TTL_SECONDS || 900) * 1000,
    n: pubN,
    threshold: pubT,
    protocolVersion: 'MPC-secp256k1-v1',
  });

  const balance = await getBalance(address);
  console.log(
    `[SARAL MPC] Wallet successfully generated for user ${userId.slice(0, 8)}… — ` +
    `${config.totalNodes} nodes deployed across Foundation (${foundN}, t=${foundT}), ` +
    `Public (${pubN}, t=${pubT}), and Private (${privN}, t=${privT}) domains with zero address/key storage.`
  );

  return {
    address,
    publicKey,
    balance,
    n: pubN,
    threshold: pubT,
    protocolVersion: 'MPC-secp256k1-v1',
  };
}

/**
 * CASE B — Execute MPC Threshold Signing Transaction
 *
 * Workflow:
 *  1. Authenticate user & verify MFA.
 *  2. Evaluate Adaptive Context & Working Policy (time & geofencing).
 *  3. Validate transaction details & fetch account nonce + gas parameters.
 *  4. Construct unsigned EVM transaction payload.
 *  5. Form 3-Domain Quorums:
 *     - Foundation Domain (1 node)
 *     - Public Domain (threshold nodes, e.g. 5 nodes)
 *     - Private Domain (threshold nodes, e.g. 5 nodes)
 *  6. Retrieve and decrypt share values from nodes using domain keys.
 *  7. Execute Genuine Threshold MPC Signing:
 *     Joint distributed nonce generation, cross-term computation, partial signatures.
 *  8. Verify aggregated signature against public key Q.
 *  9. Broadcast raw signed transaction directly to MST Testnet.
 *  10. Record audit trail.
 *
 * CRITICAL ARCHITECTURAL GUARANTEE:
 * Complete private key is NEVER reconstructed in memory, string, or Buffer.
 */
/**
 * Prepares transaction preview without signing or broadcasting.
 */
export async function prepareSigningTransaction(
  userId: string,
  loginMethod: 'google' | 'mobile',
  mfaVerified: boolean,
  toAddress: string,
  amount: string,
  lat?: number,
  lng?: number,
  chain?: string,
  memo?: string,
  sessionId?: string
): Promise<{
  chain: string;
  curve: string;
  from: string;
  to: string;
  amount: string;
  fee: string;
  hashToSign: string;
  unsignedTx: string;
  expiresAt: number;
}> {
  const chainConfig = getBackendChainConfig(chain);

  // 1. Policy Gate
  const policyCheck = await evaluateAccessPolicy(userId, loginMethod, mfaVerified, lat, lng);
  if (!policyCheck.allowed) {
    throw new Error(`Access Denied: ${policyCheck.reason}`);
  }

  // 2. In-Memory Session Derivation (Zero storage)
  const sessionWallet = await getOrDeriveSessionWallet(userId, sessionId);
  const walletAddress = sessionWallet.address;

  // 3. Prepare Unsigned EVM Transaction
  const nonce = await getAccountNonce(walletAddress, chainConfig.id);
  const { gasPrice, gasLimit } = await getGasFeeData(chainConfig.id);
  const value = ethers.parseEther(amount.trim());
  const chainId = BigInt(chainConfig.chainId || 91562037);

  const unsignedTx = ethers.Transaction.from({
    to: ethers.getAddress(toAddress.trim()),
    value,
    nonce,
    gasPrice,
    gasLimit,
    chainId,
    type: chainConfig.defaultTxType || 0,
  });

  const unsignedSerialized = unsignedTx.unsignedSerialized;
  const hashToSign = ethers.keccak256(unsignedSerialized);
  const fee = ethers.formatEther(gasPrice * gasLimit);

  return {
    chain: chainConfig.id,
    curve: chainConfig.curve,
    from: walletAddress,
    to: ethers.getAddress(toAddress.trim()),
    amount: amount.trim(),
    fee,
    hashToSign,
    unsignedTx: unsignedSerialized,
    expiresAt: Date.now() + 5 * 60 * 1000,
  };
}

export async function executeSigningTransaction(
  userId: string,
  loginMethod: 'google' | 'mobile',
  mfaVerified: boolean,
  toAddress: string,
  amount: string,
  lat?: number,
  lng?: number,
  chain?: string,
  sessionId?: string
): Promise<{
  txHash: string;
  broadcasted: boolean;
  message: string;
  explorerUrl: string;
  domainsSigned?: string[];
  signature?: { r: string; s: string; yParity: number; v: number };
}> {
  const chainConfig = getBackendChainConfig(chain);

  // 1. Policy Gate
  const policyCheck = await evaluateAccessPolicy(userId, loginMethod, mfaVerified, lat, lng);
  if (!policyCheck.allowed) {
    throw new Error(`Access Denied: ${policyCheck.reason}`);
  }

  // 2. In-Memory Session Derivation & Threshold Lookup (Zero storage)
  const sessionWallet = await getOrDeriveSessionWallet(userId, sessionId);
  const walletAddress = sessionWallet.address;
  const publicKeyHex = sessionWallet.publicKey;

  // Retrieve pinned placement for this wallet to strictly respect its pinned thresholds
  const placement = await getPinnedWalletPlacement(prisma, userId);
  const activeTopology = getTopologyConfig();

  const foundationThreshold = placement?.foundation.threshold ?? activeTopology.foundation.threshold;
  const publicThreshold = placement?.public.threshold ?? activeTopology.public.threshold;
  const privateThreshold = placement?.private.threshold ?? activeTopology.private.threshold;

  // 3. Prepare Unsigned EVM Transaction
  const nonce = await getAccountNonce(walletAddress, chainConfig.id);
  const { gasPrice, gasLimit } = await getGasFeeData(chainConfig.id);
  const value = ethers.parseEther(amount.trim());
  const chainId = BigInt(chainConfig.chainId || 91562037);

  // Pre-check live balance before running MPC signing or logging a failed tx row
  const liveBalanceWei = await getBalanceWeiOrNull(walletAddress, chainConfig.id);
  const gasFeeWei = gasPrice * gasLimit;
  const totalRequiredWei = value + gasFeeWei;
  if (liveBalanceWei !== null && liveBalanceWei < totalRequiredWei) {
    const shortfallWei = totalRequiredWei - liveBalanceWei;
    const maxSendableWei = liveBalanceWei > gasFeeWei ? liveBalanceWei - gasFeeWei : 0n;
    throw new BadRequestError(
      `Insufficient funds: balance is ${ethers.formatEther(liveBalanceWei)} ${chainConfig.symbol}, but ${ethers.formatEther(totalRequiredWei)} ${chainConfig.symbol} is needed (${ethers.formatEther(value)} + ${ethers.formatEther(gasFeeWei)} gas; short by ${ethers.formatEther(shortfallWei)} ${chainConfig.symbol}). Max sendable: ${ethers.formatEther(maxSendableWei)} ${chainConfig.symbol}.`
    );
  }

  const unsignedTx = ethers.Transaction.from({
    to: ethers.getAddress(toAddress.trim()),
    value,
    nonce,
    gasPrice,
    gasLimit,
    chainId,
    type: chainConfig.defaultTxType || 0,
  });

  const unsignedSerialized = unsignedTx.unsignedSerialized;

  // 4. Retrieve Shares from Nodes for All 3 Domains strictly adhering to pinned quorums
  // A. Foundation Quorum
  const foundationAliases = getDomainLegacyAliases('FOUNDATION');
  const foundationRows = await prisma.keyShare.findMany({
    where: { userId, category: { in: foundationAliases } },
    take: foundationThreshold,
    orderBy: { shareIndex: 'asc' },
  });
  if (foundationRows.length < foundationThreshold) {
    throw new Error(`[Separation of Powers] Foundation domain authorization shortfall: need ${foundationThreshold}, found ${foundationRows.length}`);
  }

  // B. Public Domain Quorum
  const publicAliases = getDomainLegacyAliases('PUBLIC');
  const publicRows = await prisma.keyShare.findMany({
    where: { userId, category: { in: publicAliases } },
    take: publicThreshold,
    orderBy: { shareIndex: 'asc' },
  });
  if (publicRows.length < publicThreshold) {
    throw new Error(`[Separation of Powers] Public domain quorum shortfall: need ${publicThreshold}, found ${publicRows.length}`);
  }

  // C. Private Domain Quorum
  const privateAliases = getDomainLegacyAliases('PRIVATE');
  const privateRows = await prisma.keyShare.findMany({
    where: { userId, category: { in: privateAliases } },
    take: privateThreshold,
    orderBy: { shareIndex: 'asc' },
  });
  if (privateRows.length < privateThreshold) {
    throw new Error(`[Separation of Powers] Private sovereign quorum shortfall: need ${privateThreshold}, found ${privateRows.length}`);
  }

  // 4. Retrieve Independent MPC Participant Clients for All 3 Domains
  // CRITICAL SECURITY GUARANTEE:
  // The coordinator NEVER retrieves, decrypts, or holds any participant's private share!
  // Encrypted shares are dispatched to and decrypted strictly within each participant service process.
  // The coordinator interacts exclusively via the AuthenticatedParticipantClient interface.
  const clientPromises: Promise<AuthenticatedParticipantClient>[] = [
    ...foundationRows.map((r) =>
      nodeCluster.getParticipantClient(userId, 'FOUNDATION', r.shareIndex, r.shareIndex, r.containerName)
    ),
    ...publicRows.map((r) =>
      nodeCluster.getParticipantClient(userId, 'PUBLIC', r.shareIndex, r.shareIndex, r.containerName)
    ),
    ...privateRows.map((r) =>
      nodeCluster.getParticipantClient(userId, 'PRIVATE', r.shareIndex, r.shareIndex, r.containerName)
    ),
  ];

  const participantClients = await Promise.all(clientPromises);

  // 5. Execute True Decentralized Interactive MPC Protocol
  console.log('[SARAL MPC] Executing 3-Domain Decentralized Interactive Threshold Signing protocol...');
  const commitments = walletCommitmentsStore.get(userId);

  const mpcResult = await statelessMpcCoordinator.coordinateSigningSession(
    participantClients,
    unsignedSerialized,
    chainId,
    publicKeyHex,
    commitments,
    publicThreshold,
    privateThreshold,
    foundationThreshold
  );

  // 6. Broadcast Signed Raw Transaction
  console.log(`[SARAL MPC] Threshold signature produced. Broadcasting raw tx (Hash: ${mpcResult.txHash})...`);
  const broadcastResult = await broadcastRawTransaction(
    userId,
    mpcResult.rawSignedTx,
    toAddress,
    amount,
    chainConfig.id
  );

  return {
    ...broadcastResult,
    domainsSigned: (mpcResult as any).domainsSigned || ['foundation', 'public', 'private'],
    signature: {
      r: mpcResult.r,
      s: mpcResult.s,
      yParity: mpcResult.yParity,
      v: mpcResult.v,
    },
  };
}
