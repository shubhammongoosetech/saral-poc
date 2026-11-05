import dotenv from 'dotenv';
import path from 'path';
import { z } from 'zod';

// Load .env file
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const envSchema = z
  .object({
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

    // Shamir shares (legacy — kept for backward compat with existing code)
    SHARE_TOTAL_N: z.coerce.number().min(1).max(255).default(9),
    SHARE_THRESHOLD: z.coerce.number().min(1).max(255).default(5),

    TIME_TOLERANCE_MINUTES: z.coerce.number().default(0),
    LOCATION_RADIUS_KM: z.coerce.number().default(25),

    // Dynamic Cryptographic Participant Infrastructure Configuration
    SARAL_FOUNDATION_NODES: z.coerce.number().int().min(1).default(1),
    SARAL_PUBLIC_NODES: z.coerce.number().int().min(1).default(9),
    SARAL_PRIVATE_NODES: z.coerce.number().int().min(1).default(9),

    SARAL_FOUNDATION_THRESHOLD: z.coerce.number().int().min(1).default(1),
    SARAL_PUBLIC_THRESHOLD: z.coerce.number().int().min(1).default(5),
    SARAL_PRIVATE_THRESHOLD: z.coerce.number().int().min(1).default(5),

    SARAL_TOTAL_NODES: z.coerce.number().int().min(1).optional(),

    SARAL_REUSE_EXISTING_CONTAINERS: z
      .union([z.boolean(), z.string().transform((val) => val === 'true')])
      .default(true),
    SARAL_CREATE_CONTAINERS_ON_LOGIN: z
      .union([z.boolean(), z.string().transform((val) => val === 'true')])
      .default(false),
    SARAL_PERSISTENT_NODE_STORAGE: z
      .union([z.boolean(), z.string().transform((val) => val === 'true')])
      .default(true),
  })
  .refine(
    (cfg) =>
      cfg.SARAL_FOUNDATION_THRESHOLD >= 1 &&
      cfg.SARAL_FOUNDATION_THRESHOLD <= cfg.SARAL_FOUNDATION_NODES,
    {
      message: 'Foundation threshold must satisfy: 1 <= threshold <= participants',
      path: ['SARAL_FOUNDATION_THRESHOLD'],
    }
  )
  .refine(
    (cfg) =>
      cfg.SARAL_PUBLIC_THRESHOLD >= 1 &&
      cfg.SARAL_PUBLIC_THRESHOLD <= cfg.SARAL_PUBLIC_NODES,
    {
      message: 'Public threshold must satisfy: 1 <= threshold <= participants',
      path: ['SARAL_PUBLIC_THRESHOLD'],
    }
  )
  .refine(
    (cfg) =>
      cfg.SARAL_PRIVATE_THRESHOLD >= 1 &&
      cfg.SARAL_PRIVATE_THRESHOLD <= cfg.SARAL_PRIVATE_NODES,
    {
      message: 'Private threshold must satisfy: 1 <= threshold <= participants',
      path: ['SARAL_PRIVATE_THRESHOLD'],
    }
  )
  .refine(
    (cfg) => {
      const calculatedTotal =
        cfg.SARAL_FOUNDATION_NODES + cfg.SARAL_PUBLIC_NODES + cfg.SARAL_PRIVATE_NODES;
      if (cfg.SARAL_TOTAL_NODES !== undefined) {
        return cfg.SARAL_TOTAL_NODES === calculatedTotal;
      }
      return true;
    },
    {
      message: 'SARAL_TOTAL_NODES must equal sum of Foundation, Public, and Private nodes',
      path: ['SARAL_TOTAL_NODES'],
    }
  );

// Support both SARAL_* and standard/unprefixed configuration variable names
const rawFoundationNodes =
  process.env.SARAL_FOUNDATION_NODES || process.env.FOUNDATION_PARTICIPANTS;
const rawPublicNodes =
  process.env.SARAL_PUBLIC_NODES || process.env.PUBLIC_PARTICIPANTS;
const rawPrivateNodes =
  process.env.SARAL_PRIVATE_NODES || process.env.PRIVATE_PARTICIPANTS;

const rawFoundationThresh =
  process.env.SARAL_FOUNDATION_THRESHOLD || process.env.FOUNDATION_THRESHOLD;
const rawPublicThresh =
  process.env.SARAL_PUBLIC_THRESHOLD || process.env.PUBLIC_THRESHOLD;
const rawPrivateThresh =
  process.env.SARAL_PRIVATE_THRESHOLD || process.env.PRIVATE_THRESHOLD;

const rawTotalNodes =
  process.env.SARAL_TOTAL_NODES || process.env.TOTAL_PARTICIPANTS;

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
  // MASTER_ENCRYPTION_KEY removed — replaced by per-node key derivation (D-04)
  SHARE_TOTAL_N: process.env.SHARE_TOTAL_N || process.env.SHAMIR_TOTAL_SHARES || rawPublicNodes,
  SHARE_THRESHOLD: process.env.SHARE_THRESHOLD || process.env.SHAMIR_THRESHOLD || rawPublicThresh,
  TIME_TOLERANCE_MINUTES: process.env.TIME_TOLERANCE_MINUTES,
  LOCATION_RADIUS_KM: process.env.LOCATION_RADIUS_KM,

  SARAL_FOUNDATION_NODES: rawFoundationNodes,
  SARAL_PUBLIC_NODES: rawPublicNodes,
  SARAL_PRIVATE_NODES: rawPrivateNodes,

  SARAL_FOUNDATION_THRESHOLD: rawFoundationThresh,
  SARAL_PUBLIC_THRESHOLD: rawPublicThresh,
  SARAL_PRIVATE_THRESHOLD: rawPrivateThresh,

  SARAL_TOTAL_NODES: rawTotalNodes,

  SARAL_REUSE_EXISTING_CONTAINERS: process.env.SARAL_REUSE_EXISTING_CONTAINERS,
  SARAL_CREATE_CONTAINERS_ON_LOGIN: process.env.SARAL_CREATE_CONTAINERS_ON_LOGIN,
  SARAL_PERSISTENT_NODE_STORAGE: process.env.SARAL_PERSISTENT_NODE_STORAGE,
};

const parsed = envSchema.safeParse(rawConfig);

if (!parsed.success) {
  console.error('Invalid environment configuration:', parsed.error.format());
  throw new Error('Environment configuration validation failed');
}

const calculatedTotal =
  parsed.data.SARAL_FOUNDATION_NODES +
  parsed.data.SARAL_PUBLIC_NODES +
  parsed.data.SARAL_PRIVATE_NODES;

export const env = {
  ...parsed.data,
  SARAL_TOTAL_NODES: parsed.data.SARAL_TOTAL_NODES ?? calculatedTotal,

  // Domain configuration aliases
  FOUNDATION_PARTICIPANTS: parsed.data.SARAL_FOUNDATION_NODES,
  FOUNDATION_THRESHOLD: parsed.data.SARAL_FOUNDATION_THRESHOLD,
  PUBLIC_PARTICIPANTS: parsed.data.SARAL_PUBLIC_NODES,
  PUBLIC_THRESHOLD: parsed.data.SARAL_PUBLIC_THRESHOLD,
  PRIVATE_PARTICIPANTS: parsed.data.SARAL_PRIVATE_NODES,
  PRIVATE_THRESHOLD: parsed.data.SARAL_PRIVATE_THRESHOLD,
  TOTAL_PARTICIPANTS: parsed.data.SARAL_TOTAL_NODES ?? calculatedTotal,
};
