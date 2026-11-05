/**
 * apply.ts
 *
 * Applies topology from config/topology.json to the database and node infrastructure.
 * Usage: npm run topology:apply
 */

import fs from 'fs';
import path from 'path';
import { buildClusterTopology } from './allocation';
import { nodeCluster } from '../services/nodeClusterService';

export async function applyTopology(configPath?: string): Promise<void> {
  const file = configPath || path.resolve(__dirname, '../../config/topology.json');
  if (!fs.existsSync(file)) {
    throw new Error(`Topology config file not found: ${file}`);
  }

  const raw = fs.readFileSync(file, 'utf8');
  const parsed = JSON.parse(raw);

  const N = parsed.totalNodes || 19;
  const weights = parsed.weights;
  const thresholdOverrides = {
    foundation: parsed.domains?.FOUNDATION?.threshold,
    public: parsed.domains?.PUBLIC?.threshold,
    private: parsed.domains?.PRIVATE?.threshold,
  };

  const topo = buildClusterTopology(N, weights, thresholdOverrides);
  console.log(
    `[Topology:Apply] Successfully loaded topology '${parsed.name || 'SARAL'}': ` +
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
  applyTopology()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('[Topology:Apply] Failed:', err);
      process.exit(1);
    });
}

