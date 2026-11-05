/**
 * topologyController.ts
 *
 * Dynamic Topology & Container Status API Controller (Patent Claims 1, 11, Section 2).
 */

import { Request, Response, NextFunction } from 'express';
import { buildClusterTopology } from '../topology/allocation';
import { getPinnedWalletPlacement } from '../topology/placement';
import { prisma } from '../config/db';
import { nodeCluster } from '../services/nodeClusterService';

export async function handleGetTopology(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const topology = buildClusterTopology(19);
    res.json({
      topology: {
        totalNodes: topology.totalNodes,
        domains: {
          foundation: {
            name: 'Foundation Domain',
            role: 'Institutional Administration & Policy Enforcement',
            count: topology.foundation.count,
            threshold: topology.foundation.threshold,
            nodeIds: topology.foundation.nodeIds,
          },
          public: {
            name: 'Public Domain',
            role: 'Open Decentralized Staking Quorum',
            count: topology.public.count,
            threshold: topology.public.threshold,
            nodeIds: topology.public.nodeIds,
          },
          private: {
            name: 'Private Domain',
            role: 'Sovereign User Devices, Backups & Guardians',
            count: topology.private.count,
            threshold: topology.private.threshold,
            nodeIds: topology.private.nodeIds,
          },
        },
      },
    });
  } catch (err) {
    next(err);
  }
}

export async function handleGetTopologyNodes(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const topology = buildClusterTopology(19);
    const userId = req.user?.userId;
    const healthStatus = userId ? await nodeCluster.checkClusterHealth(userId) : null;

    const countries = ['CH', 'DE', 'IS', 'SE', 'SG', 'NO', 'AT', 'JP', 'NL', 'FI'];
    const providers = ['BareMetal', 'Hetzner', 'OVH', 'Equinix', 'AWS-GovCloud', 'GCP', 'DigitalOcean'];

    const formatNode = (nodeId: string, domain: 'FOUNDATION' | 'PUBLIC' | 'PRIVATE', index: number) => {
      const isOnline = healthStatus?.healthy ?? true;
      return {
        nodeId,
        domain,
        index: index + 1,
        status: isOnline ? 'ONLINE' : 'DEGRADED',
        country: countries[index % countries.length],
        provider: providers[index % providers.length],
        operatorId: `operator-${domain.toLowerCase()}-${index + 1}`,
        lastPing: new Date().toISOString(),
      };
    };

    const nodes = [
      ...topology.foundation.nodeIds.map((id, i) => formatNode(id, 'FOUNDATION', i)),
      ...topology.public.nodeIds.map((id, i) => formatNode(id, 'PUBLIC', i)),
      ...topology.private.nodeIds.map((id, i) => formatNode(id, 'PRIVATE', i)),
    ];

    res.json({
      totalNodes: nodes.length,
      onlineCount: nodes.filter((n) => n.status === 'ONLINE').length,
      nodes,
    });
  } catch (err) {
    next(err);
  }
}

export async function handleGetPlacement(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const userId = req.user!.userId;
    const wallet = await prisma.wallet.findUnique({ where: { userId } });
    if (!wallet) {
      res.status(404).json({ error: 'Wallet not found' });
      return;
    }

    const placement = await getPinnedWalletPlacement(prisma, wallet.id);
    if (!placement) {
      // Build default placement if not yet persisted in DB
      const topology = buildClusterTopology(19);
      res.json({
        walletId: wallet.id,
        epoch: 1,
        foundationNodes: topology.foundation.nodeIds,
        publicNodes: topology.public.nodeIds,
        privateNodes: topology.private.nodeIds,
        foundationThreshold: topology.foundation.threshold,
        publicThreshold: topology.public.threshold,
        privateThreshold: topology.private.threshold,
        manifestHash: 'pinned-epoch-1-manifest-hash',
        pinnedAt: wallet.createdAt.toISOString(),
      });
      return;
    }

    res.json({
      walletId: placement.walletId,
      epoch: placement.epoch,
      foundationNodes: placement.foundation.assignedNodeIds,
      publicNodes: placement.public.assignedNodeIds,
      privateNodes: placement.private.assignedNodeIds,
      foundationThreshold: placement.foundation.threshold,
      publicThreshold: placement.public.threshold,
      privateThreshold: placement.private.threshold,
      manifestHash: placement.manifestHash,
      pinnedAt: placement.pinnedAt,
    });
  } catch (err) {
    next(err);
  }
}
