/**
 * allocation.ts
 *
 * Dynamic Topology & Domain Node Allocation Engine for SARAL.
 *
 * Patent Specifications (Paragraphs [0014]-[0017], Claim 1):
 *   - The total number of nodes N is dynamic (N >= 9).
 *   - Three trust domains: Foundation, Public, Private.
 *   - Each domain must have at least 3 nodes (n_d >= 3).
 *   - Runtime topology is driven exclusively by getTopologyConfig().
 *   - allocate() is strictly an offline / test helper and is never called at runtime.
 */

import { DomainType } from '../crypto/thresholdEcdsa';
import { getTopologyConfig, TopologyConfig } from '../config/topologyConfig';

export interface TopologyWeights {
  foundation?: number;
  public?: number;
  private?: number;
}

export interface DomainAllocation {
  domain: DomainType;
  count: number;
  threshold: number;
  nodeIds: string[];
}

export interface ClusterTopology {
  totalNodes: number;
  foundation: DomainAllocation;
  public: DomainAllocation;
  private: DomainAllocation;
}

let cachedClusterTopology: ClusterTopology | null = null;

/**
 * Computes default fault-tolerant supermajority threshold for a domain:
 *   t = floor(2n / 3) + 1
 * Always satisfies t > n / 2 and t <= n.
 */
export function computeThreshold(n: number): number {
  if (n < 1) throw new Error(`Node count must be >= 1, got ${n}`);
  if (n === 1) return 1;
  const t = Math.floor((2 * n) / 3) + 1;
  if (t <= Math.floor(n / 2)) {
    throw new Error(`Computed threshold ${t} fails strict majority t > n/2 for n=${n}`);
  }
  if (t > n) {
    throw new Error(`Computed threshold ${t} exceeds node count n=${n}`);
  }
  return t;
}

/**
 * Proportional allocation helper for offline tools and tests.
 * NEVER called by the application at runtime.
 */
export function allocate(
  N: number,
  weights?: TopologyWeights
): {
  foundation: number;
  public: number;
  private: number;
} {
  if (N < 9) {
    throw new Error(`Total node count N must be >= 9 per separation of powers, got ${N}`);
  }

  const wF = Math.max(weights?.foundation ?? 1, 0.001);
  const wP = Math.max(weights?.public ?? 1, 0.001);
  const wV = Math.max(weights?.private ?? 1, 0.001);
  const totalWeight = wF + wP + wV;

  // Proportional distribution ensuring at least 3 per domain
  const availableToDistribute = N - 9;
  const addF = Math.round((wF / totalWeight) * availableToDistribute);
  const addP = Math.round((wP / totalWeight) * availableToDistribute);
  const addV = availableToDistribute - (addF + addP);

  const foundation = 3 + addF;
  const publicCount = 3 + addP;
  const privateCount = 3 + addV;

  if (foundation < 3 || publicCount < 3 || privateCount < 3) {
    throw new Error(
      `Allocation violated minimum domain constraint (>= 3): F=${foundation}, P=${publicCount}, V=${privateCount}`
    );
  }
  if (foundation + publicCount + privateCount !== N) {
    throw new Error(
      `Allocation sum mismatch: ${foundation} + ${publicCount} + ${privateCount} != ${N}`
    );
  }

  return {
    foundation,
    public: publicCount,
    private: privateCount,
  };
}

/**
 * Builds the ClusterTopology object strictly from TopologyConfig (sourced from .env).
 * Cached per process; recomputed on restart or cache reset.
 */
export function buildClusterTopology(config?: TopologyConfig): ClusterTopology {
  if (config) {
    return constructTopology(config);
  }

  if (!cachedClusterTopology) {
    const activeConfig = getTopologyConfig();
    cachedClusterTopology = constructTopology(activeConfig);
  }
  return cachedClusterTopology;
}

function constructTopology(cfg: TopologyConfig): ClusterTopology {
  return {
    totalNodes: cfg.totalNodes,
    foundation: {
      domain: 'FOUNDATION',
      count: cfg.foundation.nodes,
      threshold: cfg.foundation.threshold,
      nodeIds: Array.from({ length: cfg.foundation.nodes }, (_, i) => `saral-foundation-${i + 1}`),
    },
    public: {
      domain: 'PUBLIC',
      count: cfg.public.nodes,
      threshold: cfg.public.threshold,
      nodeIds: Array.from({ length: cfg.public.nodes }, (_, i) => `saral-public-${i + 1}`),
    },
    private: {
      domain: 'PRIVATE',
      count: cfg.private.nodes,
      threshold: cfg.private.threshold,
      nodeIds: Array.from({ length: cfg.private.nodes }, (_, i) => `saral-private-${i + 1}`),
    },
  };
}

/**
 * Resets the cached cluster topology (used for test isolation).
 */
export function resetTopologyCache(): void {
  cachedClusterTopology = null;
}
