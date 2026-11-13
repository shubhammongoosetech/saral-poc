/**
 * SARAL Frontend API Data Contracts & Type Definitions
 */

export interface User {
  id: string;
  name?: string;
  loginMethod: 'google' | 'mobile';
  googleId?: string;
  email?: string;
  mobile?: string;
}

export interface AuthResponse {
  user: User;
  token: string;
  mfaVerified: boolean;
  hasPolicy: boolean;
  hasWallet: boolean;
}

export interface WorkPolicy {
  start_time: string;
  end_time: string;
  timezone: string;
  city: string;
  lat: number;
  lng: number;
  radius_km: number;
  set_at?: string;
}

export interface WalletData {
  address: string;
  publicKey: string;
  balance: string;
  n: number;
  threshold: number;
  createdAt?: string;
  protocolVersion?: string;
  domains?: {
    foundation: { role: string; nodes: number };
    public: { role: string; nodes: number; threshold: number };
    private: { role: string; nodes: number; threshold: number };
  };
}

export interface ClusterStatus {
  totalNodes: number;
  domainBreakdown: {
    FOUNDATION: { total: number; online: number; threshold: number };
    PUBLIC: { total: number; online: number; threshold: number };
    PRIVATE: { total: number; online: number; threshold: number };
  };
  healthy: boolean;
  activeDriver: 'docker' | 'sandbox' | 'remote';
}

export interface PolicyCheckResponse {
  allowed: boolean;
  reason: string;
  details?: {
    currentTime?: string;
    allowedWindow?: string;
    currentDistanceKm?: number;
    maxRadiusKm?: number;
    anomalyDetected?: boolean;
  };
}

export interface TransactionRecord {
  tx_hash: string;
  to_address: string;
  amount: string;
  status?: string;
  created_at: string;
}

export interface SignTransactionResult {
  success: boolean;
  error?: string;
  txHash: string;
  broadcasted: boolean;
  message: string;
  explorerUrl?: string;
}

