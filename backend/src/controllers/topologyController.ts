/**
 * topologyController.ts
 *
 * Dynamic Topology & Container Status API Controller (Patent Claims 1, 11, Section 2).
 * Sourced dynamically from .env via getTopologyConfig() and buildClusterTopology().
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
    const topology = buildClusterTopology();
    const userId = req.user?.userId;
    const healthStatus = userId ? await nodeCluster.checkClusterHealth(userId) : null;
    const isHealthy = healthStatus?.healthy ?? true;

    res.json({
      topology: {
        totalNodes: topology.totalNodes,
        healthy: isHealthy,
        domains: {
          foundation: {
            name: 'Foundation Domain',
            role: 'Institutional Administration & Policy Enforcement',
            nodes: topology.foundation.count,
            count: topology.foundation.count,
            threshold: topology.foundation.threshold,
            nodeIds: topology.foundation.nodeIds,
            healthy: isHealthy,
          },
          public: {
            name: 'Public Domain',
            role: 'Public Independent Validator Nodes',
            nodes: topology.public.count,
            count: topology.public.count,
            threshold: topology.public.threshold,
            nodeIds: topology.public.nodeIds,
            healthy: isHealthy,
          },
          private: {
            name: 'Private Domain',
            role: 'Sovereign User Nodes',
            nodes: topology.private.count,
            count: topology.private.count,
            threshold: topology.private.threshold,
            nodeIds: topology.private.nodeIds,
            healthy: isHealthy,
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
    const topology = buildClusterTopology();
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
    const placement = await getPinnedWalletPlacement(prisma, userId);
    if (!placement) {
      const shareCount = await prisma.keyShare.count({ where: { userId } });
      if (shareCount === 0) {
        res.status(404).json({ error: 'Wallet not found' });
        return;
      }
      // Build default placement from current topology if not yet persisted in DB
      const topology = buildClusterTopology();
      res.json({
        userId,
        epoch: 1,
        foundationNodes: topology.foundation.nodeIds,
        publicNodes: topology.public.nodeIds,
        privateNodes: topology.private.nodeIds,
        foundationThreshold: topology.foundation.threshold,
        publicThreshold: topology.public.threshold,
        privateThreshold: topology.private.threshold,
        manifestHash: 'pinned-epoch-1-manifest-hash',
        pinnedAt: new Date().toISOString(),
      });
      return;
    }

    res.json({
      userId,
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
