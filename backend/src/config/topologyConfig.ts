/**
 * topologyConfig.ts
 *
 * Single Source of Truth for SARAL Node Counts and Thresholds.
 *
 * Mandate:
 *   - Every node count and every threshold across the entire project comes from .env only.
 *   - The six SARAL_* variables are read exclusively in this module (or via config/env).
 *   - SARAL_TOTAL_NODES is deprecated and computed as sum of the three domain counts.
 *   - Fail-closed validation at startup:
 *       - integers only, 3 <= count <= 255 per domain
 *       - 2 <= threshold <= count per domain
 *       - threshold > count / 2 (strict majority)
 *       - totalNodes >= 9
 */

import dotenv from 'dotenv';
import path from 'path';
import fs from 'fs';

export interface DomainConfig {
  nodes: number;
  threshold: number;
}

export interface TopologyConfig {
  foundation: DomainConfig;
  public: DomainConfig;
  private: DomainConfig;
  totalNodes: number; // Always the computed sum, never read
}

/**
 * Shared fallback configuration for development and test environments only.
 * Matches backend/.env.example and documented patent baseline.
 */
export const DEFAULT_TOPOLOGY_CONFIG: TopologyConfig = Object.freeze({
  foundation: { nodes: 9, threshold: 5 },
  public: { nodes: 9, threshold: 5 },
  private: { nodes: 9, threshold: 5 },
  totalNodes: 27,
});

let hasLoggedEnvPath = false;
let hasLoggedStartup = false;
let cachedTopologyConfig: TopologyConfig | null = null;

/**
 * Loads .env from candidate paths with deterministic precedence.
 */
export function loadTopologyEnvFile(): string | null {
  const candidates = [
    path.resolve(process.cwd(), '.env'),
    path.resolve(process.cwd(), 'backend/.env'),
    path.resolve(__dirname, '../../.env'),
    path.resolve(__dirname, '../../../backend/.env'),
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      dotenv.config({ path: candidate });
      if (!hasLoggedEnvPath && process.env.NODE_ENV !== 'production' && process.env.NODE_ENV !== 'test') {
        console.log(`[TopologyConfig] Loaded environment configuration from: ${candidate}`);
        hasLoggedEnvPath = true;
      }
      return candidate;
    }
  }

  if (process.env.NODE_ENV === 'production') {
    throw new Error('[TopologyConfig] Fatal: Missing .env file in production environment');
  }
  return null;
}

// Automatically ensure .env is parsed on module load
loadTopologyEnvFile();

/**
 * Parses and strictly validates integer values. Rejects floats, non-numeric strings, and NaN.
 */
function parseStrictInteger(value: unknown, name: string): number {
  if (value === undefined || value === null || value === '') {
    throw new Error(`[TopologyConfig] Missing required integer configuration: ${name}`);
  }
  const str = String(value).trim();
  if (!/^\d+$/.test(str)) {
    throw new Error(`[TopologyConfig] Invalid non-integer value for ${name}: '${str}'. Must be a positive integer.`);
  }
  const parsed = parseInt(str, 10);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`[TopologyConfig] Integer out of safe range for ${name}: '${str}'`);
  }
  return parsed;
}

/**
 * Derives default fault-tolerant supermajority threshold: floor(2n/3) + 1.
 */
export function deriveDefaultThreshold(nodes: number): number {
  return Math.floor((2 * nodes) / 3) + 1;
}

/**
 * Validates a single domain's topology invariants.
 */
function validateDomainConfig(domain: 'Foundation' | 'Public' | 'Private', count: number, threshold: number): void {
  if (count < 3) {
    throw new Error(
      `[TopologyConfig] Invalid node count for ${domain} domain: ${count}. Each domain must have at least 3 nodes (patent minimum).`
    );
  }
  if (count > 255) {
    throw new Error(
      `[TopologyConfig] Invalid node count for ${domain} domain: ${count}. Node count cannot exceed 255.`
    );
  }
  if (threshold < 2) {
    throw new Error(
      `[TopologyConfig] Invalid threshold for ${domain} domain: ${threshold}. Threshold must be at least 2.`
    );
  }
  if (threshold > count) {
    throw new Error(
      `[TopologyConfig] Invalid threshold for ${domain} domain: threshold ${threshold} cannot exceed node count ${count}.`
    );
  }
  // Strict majority invariant: t > n / 2
  const minMajority = Math.floor(count / 2) + 1;
  if (threshold < minMajority) {
    throw new Error(
      `[TopologyConfig] Invalid threshold for ${domain} domain: threshold ${threshold} fails strict majority requirement (threshold must be > ${count / 2}, minimum ${minMajority} for ${count} nodes).`
    );
  }
}

/**
 * Parses, validates, and builds TopologyConfig from the provided environment dictionary or process.env.
 * Fail-closed: Throws on any missing production variable or invariant breach.
 */
export function buildTopologyConfigFromSource(
  envSource: Record<string, string | undefined> = process.env,
  isProduction: boolean = (envSource.NODE_ENV || process.env.NODE_ENV) === 'production'
): TopologyConfig {
  // Deprecation warning for SARAL_TOTAL_NODES if present
  if (envSource.SARAL_TOTAL_NODES !== undefined && envSource.SARAL_TOTAL_NODES !== '') {
    if (envSource.NODE_ENV !== 'test') {
      console.warn(
        `[TopologyConfig] Deprecation Notice: SARAL_TOTAL_NODES is deprecated and ignored. Total nodes is dynamically computed as the sum of Foundation, Public, and Private nodes.`
      );
    }
  }

  // 1. Foundation Domain
  let foundN: number;
  let foundT: number;
  if (isProduction) {
    if (!envSource.SARAL_FOUNDATION_NODES) {
      throw new Error('[TopologyConfig] Missing required environment variable in production: SARAL_FOUNDATION_NODES');
    }
    foundN = parseStrictInteger(envSource.SARAL_FOUNDATION_NODES, 'SARAL_FOUNDATION_NODES');
    if (envSource.SARAL_FOUNDATION_THRESHOLD) {
      foundT = parseStrictInteger(envSource.SARAL_FOUNDATION_THRESHOLD, 'SARAL_FOUNDATION_THRESHOLD');
    } else {
      foundT = deriveDefaultThreshold(foundN);
      console.log(`[TopologyConfig] SARAL_FOUNDATION_THRESHOLD missing in production; derived threshold ${foundT} from ${foundN} nodes.`);
    }
  } else {
    foundN = envSource.SARAL_FOUNDATION_NODES !== undefined
      ? parseStrictInteger(envSource.SARAL_FOUNDATION_NODES, 'SARAL_FOUNDATION_NODES')
      : DEFAULT_TOPOLOGY_CONFIG.foundation.nodes;
    foundT = envSource.SARAL_FOUNDATION_THRESHOLD !== undefined
      ? parseStrictInteger(envSource.SARAL_FOUNDATION_THRESHOLD, 'SARAL_FOUNDATION_THRESHOLD')
      : (envSource.SARAL_FOUNDATION_NODES !== undefined ? deriveDefaultThreshold(foundN) : DEFAULT_TOPOLOGY_CONFIG.foundation.threshold);
  }
  validateDomainConfig('Foundation', foundN, foundT);

  // 2. Public Domain
  let pubN: number;
  let pubT: number;
  if (isProduction) {
    if (!envSource.SARAL_PUBLIC_NODES) {
      throw new Error('[TopologyConfig] Missing required environment variable in production: SARAL_PUBLIC_NODES');
    }
    pubN = parseStrictInteger(envSource.SARAL_PUBLIC_NODES, 'SARAL_PUBLIC_NODES');
    if (envSource.SARAL_PUBLIC_THRESHOLD) {
      pubT = parseStrictInteger(envSource.SARAL_PUBLIC_THRESHOLD, 'SARAL_PUBLIC_THRESHOLD');
    } else {
      pubT = deriveDefaultThreshold(pubN);
      console.log(`[TopologyConfig] SARAL_PUBLIC_THRESHOLD missing in production; derived threshold ${pubT} from ${pubN} nodes.`);
    }
  } else {
    pubN = envSource.SARAL_PUBLIC_NODES !== undefined
      ? parseStrictInteger(envSource.SARAL_PUBLIC_NODES, 'SARAL_PUBLIC_NODES')
      : DEFAULT_TOPOLOGY_CONFIG.public.nodes;
    pubT = envSource.SARAL_PUBLIC_THRESHOLD !== undefined
      ? parseStrictInteger(envSource.SARAL_PUBLIC_THRESHOLD, 'SARAL_PUBLIC_THRESHOLD')
      : (envSource.SARAL_PUBLIC_NODES !== undefined ? deriveDefaultThreshold(pubN) : DEFAULT_TOPOLOGY_CONFIG.public.threshold);
  }
  validateDomainConfig('Public', pubN, pubT);

  // 3. Private Domain
  let privN: number;
  let privT: number;
  if (isProduction) {
    if (!envSource.SARAL_PRIVATE_NODES) {
      throw new Error('[TopologyConfig] Missing required environment variable in production: SARAL_PRIVATE_NODES');
    }
    privN = parseStrictInteger(envSource.SARAL_PRIVATE_NODES, 'SARAL_PRIVATE_NODES');
    if (envSource.SARAL_PRIVATE_THRESHOLD) {
      privT = parseStrictInteger(envSource.SARAL_PRIVATE_THRESHOLD, 'SARAL_PRIVATE_THRESHOLD');
    } else {
      privT = deriveDefaultThreshold(privN);
      console.log(`[TopologyConfig] SARAL_PRIVATE_THRESHOLD missing in production; derived threshold ${privT} from ${privN} nodes.`);
    }
  } else {
    privN = envSource.SARAL_PRIVATE_NODES !== undefined
      ? parseStrictInteger(envSource.SARAL_PRIVATE_NODES, 'SARAL_PRIVATE_NODES')
      : DEFAULT_TOPOLOGY_CONFIG.private.nodes;
    privT = envSource.SARAL_PRIVATE_THRESHOLD !== undefined
      ? parseStrictInteger(envSource.SARAL_PRIVATE_THRESHOLD, 'SARAL_PRIVATE_THRESHOLD')
      : (envSource.SARAL_PRIVATE_NODES !== undefined ? deriveDefaultThreshold(privN) : DEFAULT_TOPOLOGY_CONFIG.private.threshold);
  }
  validateDomainConfig('Private', privN, privT);

  const totalNodes = foundN + pubN + privN;
  if (totalNodes < 9) {
    throw new Error(`[TopologyConfig] Total node count ${totalNodes} is less than required separation-of-powers minimum of 9.`);
  }

  return {
    foundation: { nodes: foundN, threshold: foundT },
    public: { nodes: pubN, threshold: pubT },
    private: { nodes: privN, threshold: privT },
    totalNodes,
  };
}

/**
 * Returns the active TopologyConfig for the application process.
 * Cached per process, recomputed on process restart or explicit reset.
 */
export function getTopologyConfig(): TopologyConfig {
  if (!cachedTopologyConfig) {
    cachedTopologyConfig = buildTopologyConfigFromSource(process.env);
    if (!hasLoggedStartup && process.env.NODE_ENV !== 'test') {
      logTopologyStartup(cachedTopologyConfig);
      hasLoggedStartup = true;
    }
  }
  return cachedTopologyConfig;
}

/**
 * Prints the canonical startup line required by specification.
 */
export function logTopologyStartup(config: TopologyConfig = getTopologyConfig()): void {
  console.log(
    `Topology: Foundation ${config.foundation.nodes} (t=${config.foundation.threshold}), ` +
    `Public ${config.public.nodes} (t=${config.public.threshold}), ` +
    `Private ${config.private.nodes} (t=${config.private.threshold}), total ${config.totalNodes}`
  );
}

/**
 * Resets process-level topology config cache (primarily for test isolation).
 */
export function resetTopologyConfigCache(): void {
  cachedTopologyConfig = null;
  hasLoggedStartup = false;
}

