import path from 'path';
import { z } from 'zod';
import { getTopologyConfig, loadTopologyEnvFile } from './topologyConfig';

// Ensure .env file is loaded with precedence
loadTopologyEnvFile();

const envSchema = z.object({
  PORT: z.coerce.number().default(3001),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  DATABASE_URL: z.string().default('postgresql://postgres:secret@localhost:5432/saral'),

  // JWT / Auth secrets
  JWT_SECRET: z.string().min(32).default('saral_dev_jwt_secret_key_2024_change_me_min32'),
  JWT_EXPIRES_IN: z.string().default('15m'),
  REFRESH_TOKEN_SECRET: z
    .string()
    .min(32)
    .default('saral_refresh_secret_change_in_production_min_32_ch'),
  CSRF_SECRET: z.string().min(16).default('saral_csrf_secret_change'),

  // Frontend URL for CORS
  FRONTEND_URL: z.string().url().default('http://localhost:5173'),

  // Token TTLs
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().default(7),

  // Google OAuth
  GOOGLE_CLIENT_ID: z.string().default('your-google-client-id.apps.googleusercontent.com'),
  GOOGLE_CLIENT_SECRET: z.string().default(''),
  GOOGLE_REDIRECT_URI: z.string().default('http://localhost:5173/login'),

  // SMS
  SMS_PROVIDER_KEY: z.string().default('dev-sms-key'),

  // Blockchain
  RPC_URL: z.string().default('https://testnetrpc.mstblockchain.com'),
  CHAIN_ID: z.coerce.number().default(91562037),

  TIME_TOLERANCE_MINUTES: z.coerce.number().default(0),
  LOCATION_RADIUS_KM: z.coerce.number().default(25),

  // Storage and Node Container flags
  SARAL_REUSE_EXISTING_CONTAINERS: z
    .union([z.boolean(), z.string().transform((val) => val === 'true')])
    .default(true),
  SARAL_CREATE_CONTAINERS_ON_LOGIN: z
    .union([z.boolean(), z.string().transform((val) => val === 'true')])
    .default(false),
  SARAL_PERSISTENT_NODE_STORAGE: z
    .union([z.boolean(), z.string().transform((val) => val === 'true')])
    .default(true),

  // System runtime directories and secrets (centralized so process.env.SARAL_ is only read in config/)
  SARAL_REGISTRY_DIR: z.string().default(path.resolve(process.cwd(), '.saral_registry')),
  SARAL_VAULT_DIR: z.string().default(path.resolve(process.cwd(), '.saral_node_vault')),
  SARAL_SOCKETS_DIR: z.string().default(path.resolve(process.cwd(), '.saral_runtime_sockets')),
  SARAL_NODE_KEYS_DIR: z.string().default(path.resolve(process.cwd(), '.saral_node_keys')),
  SARAL_REGISTRY_ADMIN_SECRET: z.string().optional(),
  SARAL_IPC_AUTH_KEY: z.string().optional(),
  SARAL_NODE_ID: z.string().optional(),
  SARAL_NODE_DOMAIN: z.string().optional(),
  SARAL_NODE_INDEX: z.string().optional(),
  SARAL_SHARE_INDEX: z.string().optional(),
  SARAL_SOCKET_PATH: z.string().optional(),
});

const rawConfig = {
  PORT: process.env.PORT,
  NODE_ENV: process.env.NODE_ENV,
  DATABASE_URL: process.env.DATABASE_URL,
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN,
  REFRESH_TOKEN_SECRET: process.env.REFRESH_TOKEN_SECRET,
  CSRF_SECRET: process.env.CSRF_SECRET,
  FRONTEND_URL: process.env.FRONTEND_URL,
  ACCESS_TOKEN_TTL_SECONDS: process.env.ACCESS_TOKEN_TTL_SECONDS,
  REFRESH_TOKEN_TTL_DAYS: process.env.REFRESH_TOKEN_TTL_DAYS,
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI || process.env.GOOGLE_CALLBACK_URL,
  SMS_PROVIDER_KEY: process.env.SMS_PROVIDER_KEY,
  RPC_URL: process.env.RPC_URL,
  CHAIN_ID: process.env.CHAIN_ID,
  TIME_TOLERANCE_MINUTES: process.env.TIME_TOLERANCE_MINUTES,
  LOCATION_RADIUS_KM: process.env.LOCATION_RADIUS_KM,

  SARAL_REUSE_EXISTING_CONTAINERS: process.env.SARAL_REUSE_EXISTING_CONTAINERS,
  SARAL_CREATE_CONTAINERS_ON_LOGIN: process.env.SARAL_CREATE_CONTAINERS_ON_LOGIN,
  SARAL_PERSISTENT_NODE_STORAGE: process.env.SARAL_PERSISTENT_NODE_STORAGE,

  SARAL_REGISTRY_DIR: process.env.SARAL_REGISTRY_DIR,
  SARAL_VAULT_DIR: process.env.SARAL_VAULT_DIR,
  SARAL_SOCKETS_DIR: process.env.SARAL_SOCKETS_DIR,
  SARAL_NODE_KEYS_DIR: process.env.SARAL_NODE_KEYS_DIR,
  SARAL_REGISTRY_ADMIN_SECRET: process.env.SARAL_REGISTRY_ADMIN_SECRET,
  SARAL_IPC_AUTH_KEY: process.env.SARAL_IPC_AUTH_KEY,
  SARAL_NODE_ID: process.env.SARAL_NODE_ID,
  SARAL_NODE_DOMAIN: process.env.SARAL_NODE_DOMAIN,
  SARAL_NODE_INDEX: process.env.SARAL_NODE_INDEX,
  SARAL_SHARE_INDEX: process.env.SARAL_SHARE_INDEX,
  SARAL_SOCKET_PATH: process.env.SARAL_SOCKET_PATH,
};

const parsed = envSchema.safeParse(rawConfig);

if (!parsed.success) {
  console.error('[Env] Invalid environment configuration:', parsed.error.format());
  throw new Error('Environment configuration validation failed');
}

/**
 * Read-only proxy object exposing base environment variables and dynamic topology properties.
 * Node counts and thresholds are always sourced dynamically from getTopologyConfig().
 */
export const env = new Proxy(parsed.data as any, {
  get(target, prop: string | symbol) {
    if (typeof prop === 'string') {
      const topo = getTopologyConfig();
      switch (prop) {
        case 'SARAL_FOUNDATION_NODES':
          return topo.foundation.nodes;
        case 'SARAL_FOUNDATION_THRESHOLD':
          return topo.foundation.threshold;
        case 'SARAL_PUBLIC_NODES':
          return topo.public.nodes;
        case 'SARAL_PUBLIC_THRESHOLD':
          return topo.public.threshold;
        case 'SARAL_PRIVATE_NODES':
          return topo.private.nodes;
        case 'SARAL_PRIVATE_THRESHOLD':
          return topo.private.threshold;
        case 'SARAL_TOTAL_NODES':
          return topo.totalNodes;
      }
    }
    return target[prop];
  },
});
