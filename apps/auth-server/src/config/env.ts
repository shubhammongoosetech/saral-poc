/**
 * SARAL Protocol — Centralized Environment Configuration
 */

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
};

