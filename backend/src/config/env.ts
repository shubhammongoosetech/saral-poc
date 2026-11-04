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
    JWT_SECRET: z.string().min(16).default('saral_dev_jwt_secret_key_2024_change_me'),
    JWT_EXPIRES_IN: z.string().default('7d'),
    GOOGLE_CLIENT_ID: z.string().default('your-google-client-id.apps.googleusercontent.com'),
    GOOGLE_CLIENT_SECRET: z.string().default(''),
    GOOGLE_REDIRECT_URI: z.string().default('http://localhost:5173/login'),
    SMS_PROVIDER_KEY: z.string().default('dev-sms-key'),
    RPC_URL: z.string().default('https://testnetrpc.mstblockchain.com'),
    CHAIN_ID: z.coerce.number().default(91562037),
    MASTER_ENCRYPTION_KEY: z.string().default('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
    SHARE_TOTAL_N: z.coerce.number().min(2).max(255).default(9),
    SHARE_THRESHOLD: z.coerce.number().min(2).max(255).default(5),
    TIME_TOLERANCE_MINUTES: z.coerce.number().default(0),
    LOCATION_RADIUS_KM: z.coerce.number().default(25),

    // Fixed 19-Node Participant Infrastructure Configuration
    SARAL_FOUNDATION_NODES: z.coerce.number().int().min(1).default(1),
    SARAL_PUBLIC_NODES: z.coerce.number().int().min(1).default(9),
    SARAL_PRIVATE_NODES: z.coerce.number().int().min(1).default(9),

    SARAL_FOUNDATION_THRESHOLD: z.coerce.number().int().min(1).default(1),
    SARAL_PUBLIC_THRESHOLD: z.coerce.number().int().min(1).default(5),
    SARAL_PRIVATE_THRESHOLD: z.coerce.number().int().min(1).default(5),

    SARAL_TOTAL_NODES: z.coerce.number().int().min(1).default(19),

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
    (cfg) => cfg.SARAL_FOUNDATION_NODES === 1 && cfg.SARAL_FOUNDATION_THRESHOLD === 1,
    {
      message: 'Foundation domain topology must be exactly 1 node with threshold 1 (1-of-1)',
      path: ['SARAL_FOUNDATION_THRESHOLD'],
    }
  )
  .refine(
    (cfg) => cfg.SARAL_PUBLIC_NODES === 9 && cfg.SARAL_PUBLIC_THRESHOLD === 5,
    {
      message: 'Public domain topology must be exactly 9 nodes with threshold 5 (5-of-9)',
      path: ['SARAL_PUBLIC_THRESHOLD'],
    }
  )
  .refine(
    (cfg) => cfg.SARAL_PRIVATE_NODES === 9 && cfg.SARAL_PRIVATE_THRESHOLD === 5,
    {
      message: 'Private domain topology must be exactly 9 nodes with threshold 5 (5-of-9)',
      path: ['SARAL_PRIVATE_THRESHOLD'],
    }
  )
  .refine(
    (cfg) =>
      cfg.SARAL_TOTAL_NODES ===
      cfg.SARAL_FOUNDATION_NODES + cfg.SARAL_PUBLIC_NODES + cfg.SARAL_PRIVATE_NODES,
    {
      message:
        'SARAL_TOTAL_NODES must equal sum of Foundation, Public, and Private nodes (exactly 19)',
      path: ['SARAL_TOTAL_NODES'],
    }
  );

// Support fallback variable names if set
const rawConfig = {
  PORT: process.env.PORT,
  NODE_ENV: process.env.NODE_ENV,
  DATABASE_URL: process.env.DATABASE_URL,
  JWT_SECRET: process.env.JWT_SECRET,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN,
  GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI: process.env.GOOGLE_REDIRECT_URI || process.env.GOOGLE_CALLBACK_URL,
  SMS_PROVIDER_KEY: process.env.SMS_PROVIDER_KEY,
  RPC_URL: process.env.RPC_URL,
  CHAIN_ID: process.env.CHAIN_ID,
  MASTER_ENCRYPTION_KEY: process.env.MASTER_ENCRYPTION_KEY || process.env.ENCRYPTION_KEY,
  SHARE_TOTAL_N: process.env.SHARE_TOTAL_N || process.env.SHAMIR_TOTAL_SHARES,
  SHARE_THRESHOLD: process.env.SHARE_THRESHOLD || process.env.SHAMIR_THRESHOLD,
  TIME_TOLERANCE_MINUTES: process.env.TIME_TOLERANCE_MINUTES,
  LOCATION_RADIUS_KM: process.env.LOCATION_RADIUS_KM,

  SARAL_FOUNDATION_NODES: process.env.SARAL_FOUNDATION_NODES,
  SARAL_PUBLIC_NODES: process.env.SARAL_PUBLIC_NODES,
  SARAL_PRIVATE_NODES: process.env.SARAL_PRIVATE_NODES,

  SARAL_FOUNDATION_THRESHOLD: process.env.SARAL_FOUNDATION_THRESHOLD,
  SARAL_PUBLIC_THRESHOLD: process.env.SARAL_PUBLIC_THRESHOLD,
  SARAL_PRIVATE_THRESHOLD: process.env.SARAL_PRIVATE_THRESHOLD,

  SARAL_TOTAL_NODES: process.env.SARAL_TOTAL_NODES,

  SARAL_REUSE_EXISTING_CONTAINERS: process.env.SARAL_REUSE_EXISTING_CONTAINERS,
  SARAL_CREATE_CONTAINERS_ON_LOGIN: process.env.SARAL_CREATE_CONTAINERS_ON_LOGIN,
  SARAL_PERSISTENT_NODE_STORAGE: process.env.SARAL_PERSISTENT_NODE_STORAGE,
};

const parsed = envSchema.safeParse(rawConfig);

if (!parsed.success) {
  console.error('Invalid environment configuration:', parsed.error.format());
  throw new Error('Environment configuration validation failed');
}

export const env = parsed.data;
