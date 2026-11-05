/**
 * nodeLauncher.ts
 *
 * Standalone Node Process Launcher for Dynamic SARAL Trust Domains.
 *
 * CLI Usage:
 *   npm run nodes:start -- --foundation 7 --public 6 --private 6
 *   npm run nodes:start -- --nodes 27
 */

import { spawn, ChildProcess } from 'child_process';
import path from 'path';
import fs from 'fs';
import { allocate, computeThreshold } from '../topology/allocation';
import { nodeCluster } from '../services/nodeClusterService';

export interface LaunchedProcessInfo {
  nodeId: string;
  domain: string;
  nodeIndex: number;
  pid: number;
}

export class DynamicNodeLauncher {
  private processes = new Map<string, ChildProcess>();

  /**
   * Spawns all standalone node processes according to the specified domain breakdown.
   */
  public async launchCluster(options: {
    foundation: number;
    public: number;
    private: number;
  }): Promise<LaunchedProcessInfo[]> {
    const { foundation, public: pubCount, private: privCount } = options;
    const launched: LaunchedProcessInfo[] = [];

    const domains = [
      { domain: 'FOUNDATION' as const, count: foundation },
      { domain: 'PUBLIC' as const, count: pubCount },
      { domain: 'PRIVATE' as const, count: privCount },
    ];

    console.log(
      `[NodeLauncher] Starting ${foundation + pubCount + privCount} standalone processes: ` +
      `Foundation (${foundation}), Public (${pubCount}), Private (${privCount})...`
    );

    for (const { domain, count } of domains) {
      for (let i = 1; i <= count; i++) {
        const nodeId = `saral-${domain.toLowerCase()}-${i}`;
        const info = await nodeCluster.ensureParticipantProcessRunning(nodeId, domain, i, i);
        if (info.pid) {
          launched.push({
            nodeId,
            domain,
            nodeIndex: i,
            pid: info.pid,
          });
        }
      }
    }

    console.log(`[NodeLauncher] All ${launched.length} node processes are running and healthy.`);
    return launched;
  }

  /**
   * Graceful termination of all spawned processes.
   */
  public shutdown(): void {
    for (const [id, proc] of this.processes) {
      try {
        proc.kill('SIGTERM');
      } catch {}
    }
    this.processes.clear();
  }
}

export const dynamicNodeLauncher = new DynamicNodeLauncher();

// CLI Entrypoint
if (require.main === module) {
  const args = process.argv.slice(2);
  let f = 7;
  let p = 6;
  let v = 6;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--foundation' && args[i + 1]) f = parseInt(args[i + 1], 10);
    if (args[i] === '--public' && args[i + 1]) p = parseInt(args[i + 1], 10);
    if (args[i] === '--private' && args[i + 1]) v = parseInt(args[i + 1], 10);
    if (args[i] === '--nodes' && args[i + 1]) {
      const total = parseInt(args[i + 1], 10);
      const alloc = allocate(total);
      f = alloc.foundation;
      p = alloc.public;
      v = alloc.private;
    }
  }

  dynamicNodeLauncher
    .launchCluster({ foundation: f, public: p, private: v })
    .then((procs) => {
      console.log(`[NodeLauncher] Successfully initialized ${procs.length} nodes.`);
    })
    .catch((err) => {
      console.error('[NodeLauncher] Launch failed:', err);
      process.exit(1);
    });
}

