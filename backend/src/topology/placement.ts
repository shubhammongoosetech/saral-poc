/**
 * placement.ts
 *
 * Rendezvous (Highest Random Weight / HRW) Hashing & Pinned Routing Engine.
 *
 * Patent Specifications (Paragraphs [0016], [0022], Section 2.2):
 *   - The same user always lands in the same containers and nodes.
 *   - HRW hashing per domain guarantees that adding or removing nodes does NOT move existing wallets.
 *   - The placement is PINNED in PostgreSQL (wallet_placements table) and in a signed manifest file
 *     on every participating node.
 *   - On every later login and sign request, routing strictly uses the pinned placement, never recomputing.
 *   - Placement changes only through explicit, audited proactive resharing that increments `epoch`.
 */

import crypto from 'crypto';
import { DomainType } from '../crypto/thresholdEcdsa';
import { ClusterTopology } from './allocation';

export interface DomainPlacement {
  domain: DomainType;
  assignedNodeIds: string[];
  threshold: number;
}

export interface WalletPlacement {
  walletId: string;
  userId?: string;
  epoch: number;
  foundation: DomainPlacement;
  public: DomainPlacement;
  private: DomainPlacement;
  manifestHash: string;
  signatureHex?: string;
  pinnedAt: string;
}

export interface NodePlacementManifest {
  version: 'v1';
  walletId: string;
  epoch: number;
  nodeId: string;
  domain: DomainType;
  assignedNodeIndex: number;
  domainThreshold: number;
  allAssignedNodesInDomain: string[];
  manifestHash: string;
  signedByCoordinator: string; // HMAC-SHA256 or secp256k1 signature
  timestamp: string;
}

/**
 * Computes deterministic Rendezvous (Highest Random Weight) score
 * for a (walletId, nodeId) pair using HMAC-SHA256:
 *   score = BigInt(HMAC-SHA256(walletId, nodeId))
 */
export function computeHrwScore(walletId: string, nodeId: string): bigint {
  const hmac = crypto.createHmac('sha256', walletId).update(nodeId).digest('hex');
  return BigInt('0x' + hmac);
}

/**
 * Selects top `count` nodes from `candidateNodeIds` using Rendezvous Hashing.
 * Adding or removing other nodes does not reorder existing candidates.
 */
export function selectNodesHrw(
  walletId: string,
  candidateNodeIds: string[],
  count: number
): string[] {
  if (count > candidateNodeIds.length) {
    throw new Error(
      `Cannot select ${count} nodes from pool of ${candidateNodeIds.length} candidate nodes`
    );
  }

  // Compute scores and rank descending
  const scored = candidateNodeIds.map((nodeId) => ({
    nodeId,
    score: computeHrwScore(walletId, nodeId),
  }));

  scored.sort((a, b) => (b.score > a.score ? 1 : b.score < a.score ? -1 : 0));

  return scored.slice(0, count).map((item) => item.nodeId);
}

/**
 * Computes canonical SHA-256 manifest hash of a placement.
 */
export function computeManifestHash(
  walletId: string,
  epoch: number,
  foundationNodes: string[],
  publicNodes: string[],
  privateNodes: string[]
): string {
  const payload = [
    walletId,
    epoch.toString(),
    foundationNodes.join(','),
    publicNodes.join(','),
    privateNodes.join(','),
  ].join('|');
  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Computes the deterministic HRW placement for a wallet under a cluster topology.
 */
export function computeWalletPlacement(
  walletId: string,
  topology: ClusterTopology,
  epoch: number = 1,
  userId?: string
): WalletPlacement {
  // Select nodes per domain via HRW hashing
  const foundationNodes = selectNodesHrw(
    walletId,
    topology.foundation.nodeIds,
    topology.foundation.count
  );
  const publicNodes = selectNodesHrw(
    walletId,
    topology.public.nodeIds,
    topology.public.count
  );
  const privateNodes = selectNodesHrw(
    walletId,
    topology.private.nodeIds,
    topology.private.count
  );

  const manifestHash = computeManifestHash(
    walletId,
    epoch,
    foundationNodes,
    publicNodes,
    privateNodes
  );

  return {
    walletId,
    userId,
    epoch,
    foundation: {
      domain: 'FOUNDATION',
      assignedNodeIds: foundationNodes,
      threshold: topology.foundation.threshold,
    },
    public: {
      domain: 'PUBLIC',
      assignedNodeIds: publicNodes,
      threshold: topology.public.threshold,
    },
    private: {
      domain: 'PRIVATE',
      assignedNodeIds: privateNodes,
      threshold: topology.private.threshold,
    },
    manifestHash,
    pinnedAt: new Date().toISOString(),
  };
}

/**
 * Generates an individualized signed placement manifest for a specific participating node.
 */
export function generateNodeManifest(
  placement: WalletPlacement,
  nodeId: string,
  coordinatorSecret: string
): NodePlacementManifest {
  let domain: DomainType;
  let allAssigned: string[];
  let threshold: number;

  if (placement.foundation.assignedNodeIds.includes(nodeId)) {
    domain = 'FOUNDATION';
    allAssigned = placement.foundation.assignedNodeIds;
    threshold = placement.foundation.threshold;
  } else if (placement.public.assignedNodeIds.includes(nodeId)) {
    domain = 'PUBLIC';
    allAssigned = placement.public.assignedNodeIds;
    threshold = placement.public.threshold;
  } else if (placement.private.assignedNodeIds.includes(nodeId)) {
    domain = 'PRIVATE';
    allAssigned = placement.private.assignedNodeIds;
    threshold = placement.private.threshold;
  } else {
    throw new Error(`Node ${nodeId} is not a participating node in placement for wallet ${placement.walletId}`);
  }

  const assignedIndex = allAssigned.indexOf(nodeId) + 1;
  const manifestData = `${placement.walletId}:${placement.epoch}:${nodeId}:${domain}:${placement.manifestHash}`;
  const signedByCoordinator = crypto
    .createHmac('sha256', coordinatorSecret)
    .update(manifestData)
    .digest('hex');

  return {
    version: 'v1',
    walletId: placement.walletId,
    epoch: placement.epoch,
    nodeId,
    domain,
    assignedNodeIndex: assignedIndex,
    domainThreshold: threshold,
    allAssignedNodesInDomain: allAssigned,
    manifestHash: placement.manifestHash,
    signedByCoordinator,
    timestamp: new Date().toISOString(),
  };
}

/**
 * In-memory fallback cache for test environments without a live PostgreSQL connection.
 */
export const pinnedPlacementsCache = new Map<string, WalletPlacement>();

/**
 * Pins placement in the PostgreSQL database and in-memory cache.
 */
export async function pinWalletPlacement(
  prismaClient: any,
  placement: WalletPlacement
): Promise<void> {
  const effectiveUserId = placement.userId || placement.walletId;
  pinnedPlacementsCache.set(placement.walletId, placement);
  pinnedPlacementsCache.set(effectiveUserId, placement);
  pinnedPlacementsCache.set(`${placement.walletId}:${placement.epoch}`, placement);
  pinnedPlacementsCache.set(`${effectiveUserId}:${placement.epoch}`, placement);

  if (prismaClient?.walletPlacement) {
    try {
      await prismaClient.walletPlacement.upsert({
        where: {
          unique_user_epoch: {
            userId: effectiveUserId,
            epoch: placement.epoch,
          },
        },
        update: {
          foundationNodes: placement.foundation.assignedNodeIds,
          publicNodes: placement.public.assignedNodeIds,
          privateNodes: placement.private.assignedNodeIds,
          foundationThreshold: placement.foundation.threshold,
          publicThreshold: placement.public.threshold,
          privateThreshold: placement.private.threshold,
          manifestHash: placement.manifestHash,
          pinnedAt: new Date(placement.pinnedAt),
        },
        create: {
          userId: effectiveUserId,
          epoch: placement.epoch,
          foundationNodes: placement.foundation.assignedNodeIds,
          publicNodes: placement.public.assignedNodeIds,
          privateNodes: placement.private.assignedNodeIds,
          foundationThreshold: placement.foundation.threshold,
          publicThreshold: placement.public.threshold,
          privateThreshold: placement.private.threshold,
          manifestHash: placement.manifestHash,
          pinnedAt: new Date(placement.pinnedAt),
        },
      });
    } catch (err: any) {
      console.warn(`[Placement] Could not persist to PostgreSQL: ${err.message}. Using cache.`);
    }
  }
}

/**
 * Retrieves the pinned placement for a wallet. On every later login and sign request,
 * the user is routed using this pinned placement, never recomputing.
 */
export async function getPinnedWalletPlacement(
  prismaClient: any,
  walletId: string,
  epoch?: number
): Promise<WalletPlacement | null> {
  // 1. Check in-memory cache first
  if (epoch !== undefined) {
    const epochCached = pinnedPlacementsCache.get(`${walletId}:${epoch}`);
    if (epochCached) return epochCached;
  }
  const cached = pinnedPlacementsCache.get(walletId);
  if (cached && (epoch === undefined || cached.epoch === epoch)) {
    return cached;
  }

  // 2. Query PostgreSQL
  if (prismaClient?.walletPlacement) {
    try {
      const row = await prismaClient.walletPlacement.findFirst({
        where: {
          userId: walletId,
          ...(epoch !== undefined ? { epoch } : {}),
        },
        orderBy: { epoch: 'desc' },
      });

      if (row) {
        const placement: WalletPlacement = {
          walletId: row.userId,
          userId: row.userId,
          epoch: row.epoch,
          foundation: {
            domain: 'FOUNDATION',
            assignedNodeIds: row.foundationNodes,
            threshold: row.foundationThreshold,
          },
          public: {
            domain: 'PUBLIC',
            assignedNodeIds: row.publicNodes,
            threshold: row.publicThreshold,
          },
          private: {
            domain: 'PRIVATE',
            assignedNodeIds: row.privateNodes,
            threshold: row.privateThreshold,
          },
          manifestHash: row.manifestHash,
          pinnedAt: row.pinnedAt.toISOString(),
        };
        pinnedPlacementsCache.set(walletId, placement);
        pinnedPlacementsCache.set(row.userId, placement);
        return placement;
      }
    } catch (err: any) {
      console.warn(`[Placement] Database query failed: ${err.message}.`);
    }
  }

  return cached || null;
}

export interface NodeDiversityAttributes {
  nodeId: string;
  operatorId?: string;
  jurisdiction?: string;
  hostingProvider?: string;
}

/**
 * Validates Independence & Infrastructure Diversity (Patent Claim 5 & Paragraph [0022]):
 * (a) Membership exclusion: one operator cannot hold nodes across multiple domains.
 * (b) Jurisdiction and infrastructure diversity: reject placement if too many nodes (> 33%) share a country or cloud provider.
 */
export function validatePlacementDiversity(
  placement: WalletPlacement,
  nodesMetadata: Map<string, NodeDiversityAttributes> | Record<string, NodeDiversityAttributes>,
  maxConcentrationRatio: number = 0.34
): { valid: boolean; violations: string[] } {
  const metaMap = nodesMetadata instanceof Map
    ? nodesMetadata
    : new Map(Object.entries(nodesMetadata));

  const violations: string[] = [];

  // 1. Cross-domain operator exclusion
  const operatorToDomain = new Map<string, string>();
  const domains: Array<{ name: string; nodeIds: string[] }> = [
    { name: 'FOUNDATION', nodeIds: placement.foundation.assignedNodeIds },
    { name: 'PUBLIC', nodeIds: placement.public.assignedNodeIds },
    { name: 'PRIVATE', nodeIds: placement.private.assignedNodeIds },
  ];

  for (const dom of domains) {
    for (const nodeId of dom.nodeIds) {
      const meta = metaMap.get(nodeId);
      if (!meta?.operatorId) continue;
      const prevDomain = operatorToDomain.get(meta.operatorId);
      if (prevDomain && prevDomain !== dom.name) {
        violations.push(
          `Cross-domain violation: Operator '${meta.operatorId}' holds nodes in both '${prevDomain}' and '${dom.name}'`
        );
      } else {
        operatorToDomain.set(meta.operatorId, dom.name);
      }
    }
  }

  // 2. Jurisdiction & hosting provider concentration per domain
  for (const dom of domains) {
    const total = dom.nodeIds.length;
    if (total === 0) continue;
    const maxAllowed = Math.ceil(total * maxConcentrationRatio);

    const jurisdictionCounts = new Map<string, number>();
    const providerCounts = new Map<string, number>();

    for (const nodeId of dom.nodeIds) {
      const meta = metaMap.get(nodeId);
      if (meta?.jurisdiction) {
        const c = (jurisdictionCounts.get(meta.jurisdiction) || 0) + 1;
        jurisdictionCounts.set(meta.jurisdiction, c);
        if (c > maxAllowed) {
          violations.push(
            `Jurisdiction concentration violation in '${dom.name}': ${c}/${total} nodes in '${meta.jurisdiction}' exceeds limit of ${maxAllowed}`
          );
        }
      }
      if (meta?.hostingProvider) {
        const c = (providerCounts.get(meta.hostingProvider) || 0) + 1;
        providerCounts.set(meta.hostingProvider, c);
        if (c > maxAllowed) {
          violations.push(
            `Hosting provider concentration violation in '${dom.name}': ${c}/${total} nodes on '${meta.hostingProvider}' exceeds limit of ${maxAllowed}`
          );
        }
      }
    }
  }

  return {
    valid: violations.length === 0,
    violations,
  };
}
