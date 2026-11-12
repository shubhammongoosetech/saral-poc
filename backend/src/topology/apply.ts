/**
 * apply.ts
 *
 * Applies active topology from .env (or explicit CLI overrides) to the database and node infrastructure.
 * Usage:
 *   npm run topology:apply
 *   npm run topology:apply -- --config path/to/topology.json
 */

import fs from 'fs';
import path from 'path';
import { buildClusterTopology, ClusterTopology } from './allocation';
import { getTopologyConfig, TopologyConfig } from '../config/topologyConfig';
import { nodeCluster } from '../services/nodeClusterService';

export async function applyTopology(customConfig?: TopologyConfig): Promise<void> {
  const topo: ClusterTopology = customConfig ? buildClusterTopology(customConfig) : buildClusterTopology();

  console.log(
    `[Topology:Apply] Successfully loaded topology: ` +
    `Total=${topo.totalNodes} | Foundation=${topo.foundation.count} (t=${topo.foundation.threshold}) | ` +
    `Public=${topo.public.count} (t=${topo.public.threshold}) | ` +
    `Private=${topo.private.count} (t=${topo.private.threshold})`
  );

  // Initialize nodes and local enrollment
  const result = await nodeCluster.ensureInfrastructureReady({
    FOUNDATION: { count: topo.foundation.count, threshold: topo.foundation.threshold },
    PUBLIC: { count: topo.public.count, threshold: topo.public.threshold },
    PRIVATE: { count: topo.private.count, threshold: topo.private.threshold },
  });

  console.log(`[Topology:Apply] Infrastructure ready: ${result.initialized} of ${result.totalNodes} nodes active.`);
}

if (require.main === module) {
  const args = process.argv.slice(2);
  let configOverride: TopologyConfig | undefined;

  const configArgIdx = args.indexOf('--config');
  if (configArgIdx !== -1 && args[configArgIdx + 1]) {
    const file = path.resolve(process.cwd(), args[configArgIdx + 1]);
    if (!fs.existsSync(file)) {
      console.error(`[Topology:Apply] Configuration file not found: ${file}`);
      process.exit(1);
    }
    const raw = fs.readFileSync(file, 'utf8');
    const parsed = JSON.parse(raw);
    console.log(`[Topology:Apply] Overriding default topology from file: ${file}`);

    const fNodes = parsed.domains?.FOUNDATION?.nodes ?? parsed.foundation ?? 9;
    const fThresh = parsed.domains?.FOUNDATION?.threshold ?? 5;
    const pNodes = parsed.domains?.PUBLIC?.nodes ?? parsed.public ?? 9;
    const pThresh = parsed.domains?.PUBLIC?.threshold ?? 5;
    const vNodes = parsed.domains?.PRIVATE?.nodes ?? parsed.private ?? 9;
    const vThresh = parsed.domains?.PRIVATE?.threshold ?? 5;

    configOverride = {
      foundation: { nodes: fNodes, threshold: fThresh },
      public: { nodes: pNodes, threshold: pThresh },
      private: { nodes: vNodes, threshold: vThresh },
      totalNodes: fNodes + pNodes + vNodes,
    };
  }

  applyTopology(configOverride)
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[Topology:Apply] Failed:', err);
      process.exit(1);
    });
}
