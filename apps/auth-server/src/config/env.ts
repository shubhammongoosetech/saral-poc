/**
 * SARAL Protocol — Centralized Environment Configuration
 *
 * Enforces 3-Domain Separation of Powers:
 * - Foundation Domain (Governance & Genesis)
 * - Public Domain (Decentralized Relays & External Verifiers)
 * - Private Domain (Enterprise & Compliance)
 */

export type DomainName = 'foundation' | 'public' | 'private';

export interface DomainConfig {
  name: DomainName;
  committeeId: string;
  coordinatorUrl: string;
  n: number;
  k: number;
  t: number;
  nodeIds: string[];
}

export function parseDomainsConfig(): DomainConfig[] {
  const domainNames: DomainName[] = ['foundation', 'public', 'private'];
  const configs: DomainConfig[] = [];
  const seenNodeIds = new Set<string>();

  for (const name of domainNames) {
    const upper = name.toUpperCase();
    const envKeyNodes = `SARAL_${upper}_NODES`;
    const envKeyThreshold = `SARAL_${upper}_THRESHOLD`;
    const envKeyUrl = `${upper}_COORDINATOR_URL`;
    const envKeyPrefix = `SARAL_${upper}_NODE_PREFIX`;
    const envKeyNodeIds = `SARAL_${upper}_NODE_IDS`;

    const rawUrl =
      process.env[envKeyUrl] ||
      (name === 'foundation' ? process.env.COORDINATOR_URL : undefined) ||
      (name === 'foundation' ? 'http://localhost:9001' : name === 'public' ? 'http://localhost:9002' : 'http://localhost:9003');

    if (!rawUrl || typeof rawUrl !== 'string' || !/^https?:\/\//i.test(rawUrl.trim())) {
      throw new Error(`[Config Error] Missing or invalid coordinator URL for domain "${name}": "${rawUrl}"`);
    }
    const coordinatorUrl = rawUrl.trim().replace(/\/$/, '');

    const rawN = process.env[envKeyNodes];
    const n = rawN !== undefined ? parseInt(rawN, 10) : 5;
    if (isNaN(n) || n < 1) {
      throw new Error(`[Config Error] Invalid node count for domain "${name}": ${rawN}. Must be an integer >= 1.`);
    }

    const rawK = process.env[envKeyThreshold];
    const k = rawK !== undefined ? parseInt(rawK, 10) : 3;
    if (isNaN(k) || k < 1 || k > n) {
      throw new Error(
        `[Config Error] Invalid threshold for domain "${name}": ${rawK}. Must satisfy 1 <= threshold (${k}) <= nodes (${n}).`
      );
    }

    // Byzantine fault tolerance constraint: n - 2t >= k, n > 3t
    // For n=5, k=3 -> t=1. For n=15, k=9 -> t=3.
    let t = Math.max(1, Math.floor((n - k) / 2));
    if (t < 1) t = 1;

    // Resolve node IDs
    let nodeIds: string[] = [];
    const explicitIds = process.env[envKeyNodeIds];
    if (explicitIds && explicitIds.trim()) {
      nodeIds = explicitIds
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
    } else {
      const prefix = process.env[envKeyPrefix] || `saral-${name}-`;
      nodeIds = Array.from({ length: n }, (_, i) => `${prefix}${i + 1}`);
    }

    if (nodeIds.length !== n) {
      throw new Error(
        `[Config Error] Domain "${name}" configured with n=${n} but received ${nodeIds.length} node IDs: ${JSON.stringify(nodeIds)}`
      );
    }

    for (const nid of nodeIds) {
      if (!nid || typeof nid !== 'string') {
        throw new Error(`[Config Error] Domain "${name}" contains empty or invalid node ID: "${nid}"`);
      }
      if (seenNodeIds.has(nid)) {
        throw new Error(`[Config Error] Duplicate node ID across domains detected: "${nid}"`);
      }
      seenNodeIds.add(nid);
    }

    configs.push({
      name,
      committeeId: `committee-${name}`,
      coordinatorUrl,
      n,
      k,
      t,
      nodeIds,
    });
  }

  // Verify all 3 required domains are present
  if (configs.length !== 3) {
    throw new Error(`[Config Error] Exactly 3 domains required (foundation, public, private). Found ${configs.length}.`);
  }

  const totalNodes = configs.reduce((acc, c) => acc + c.n, 0);
  if (seenNodeIds.size !== totalNodes) {
    throw new Error(
      `[Config Error] Total unique nodes (${seenNodeIds.size}) does not match sum of domain nodes (${totalNodes}).`
    );
  }

  return configs;
}

export const DOMAINS: DomainConfig[] = parseDomainsConfig();

export const DOMAINS_MAP: Record<DomainName, DomainConfig> = {
  foundation: DOMAINS.find((d) => d.name === 'foundation')!,
  public: DOMAINS.find((d) => d.name === 'public')!,
  private: DOMAINS.find((d) => d.name === 'private')!,
};

// Production secrets validation (FIX 8)
function validateProductionSecrets(): void {
  const isProd = process.env.NODE_ENV === 'production';
  const jwt = process.env.JWT_SECRET || 'saral_dev_jwt_secret_key_2024_change_me_min32';
  const mfa = process.env.MFA_ENCRYPTION_KEY || 'saral-mfa-protection-key-2026-v3';
  const otp = process.env.OTP_PEPPER || 'saral-otp-cryptographic-pepper-2026';
  const internalToken = process.env.SARAL_INTERNAL_TOKEN || '';

  if (isProd) {
    if (jwt.length < 32 || jwt.includes('change_me') || jwt.includes('dev')) {
      throw new Error(
        '[Security Config Error] Production startup refused: JWT_SECRET must be at least 32 characters and cannot contain "dev" or "change_me".'
      );
    }
    if (mfa.length < 32) {
      throw new Error(
        '[Security Config Error] Production startup refused: MFA_ENCRYPTION_KEY must be at least 32 characters in production.'
      );
    }
    if (otp.length < 32) {
      throw new Error(
        '[Security Config Error] Production startup refused: OTP_PEPPER must be at least 32 characters in production.'
      );
    }
    if (!internalToken || internalToken.length < 16) {
      throw new Error(
        '[Security Config Error] Production startup refused: SARAL_INTERNAL_TOKEN is required and must be at least 16 characters in production.'
      );
    }
  } else if (!process.env.NODE_ENV || process.env.NODE_ENV === 'development') {
    if (jwt.includes('change_me') || mfa.length < 32 || otp.length < 32) {
      console.warn('[Security Warning] Running with development cryptographic secrets. Do NOT use these in production!');
    }
  }
}

validateProductionSecrets();

export const env = {
  PORT: parseInt(process.env.PORT || '3001', 10),
  NODE_ENV: process.env.NODE_ENV || 'development',
  isDev: (process.env.NODE_ENV || 'development') === 'development',
  isTest: process.env.NODE_ENV === 'test',
  isProd: process.env.NODE_ENV === 'production',

  // Database
  DATABASE_URL:
    process.env.DATABASE_URL ||
    'postgresql://saral:saral_secret@localhost:5432/saral',

  // Secrets & Keys
  JWT_SECRET: process.env.JWT_SECRET || 'saral_dev_jwt_secret_key_2024_change_me_min32',
  MFA_ENCRYPTION_KEY: process.env.MFA_ENCRYPTION_KEY || 'saral-mfa-protection-key-2026-v3',
  OTP_PEPPER: process.env.OTP_PEPPER || 'saral-otp-cryptographic-pepper-2026',
  ENABLE_DEV_AUTH: process.env.ENABLE_DEV_AUTH === 'true',
  SARAL_INTERNAL_TOKEN: process.env.SARAL_INTERNAL_TOKEN || '',
  SARAL_DKG_TIMEOUT_MS: parseInt(process.env.SARAL_DKG_TIMEOUT_MS || '15000', 10),

  // Client URLs & OAuth
  FRONTEND_URL: process.env.FRONTEND_URL || 'http://localhost:5173',
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID || '558208753253-gr5lji587t11l5m63d5udea4msbvbcds.apps.googleusercontent.com',
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET || '',
  GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI || 'http://localhost:5173/login',

  // Blockchain RPC
  MST_RPC_URL: process.env.MST_RPC_URL || 'https://testnetrpc.mstblockchain.com',
  CHAIN_ID: parseInt(process.env.CHAIN_ID || '91562037', 10),
  SOLANA_RPC_URL: process.env.SOLANA_RPC_URL || 'https://api.devnet.solana.com',
  BITCOIN_API_URL: process.env.BITCOIN_API_URL || 'https://blockstream.info/testnet/api',

  // SARAL Go Backend (3 Domains)
  COORDINATOR_URL: DOMAINS_MAP.foundation.coordinatorUrl,
  FOUNDATION_COORDINATOR_URL: DOMAINS_MAP.foundation.coordinatorUrl,
  PUBLIC_COORDINATOR_URL: DOMAINS_MAP.public.coordinatorUrl,
  PRIVATE_COORDINATOR_URL: DOMAINS_MAP.private.coordinatorUrl,

  // Domains Config
  DOMAINS,
  DOMAINS_MAP,
  TOTAL_NODES: DOMAINS.reduce((acc, c) => acc + c.n, 0),
};
