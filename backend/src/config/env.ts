import dotenv from 'dotenv';
import path from 'path';
import { z } from 'zod';

// Load .env file
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

const envSchema = z.object({
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
});

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
};

const parsed = envSchema.safeParse(rawConfig);

if (!parsed.success) {
  console.error('Invalid environment configuration:', parsed.error.format());
  throw new Error('Environment configuration validation failed');
}

export const env = parsed.data;
