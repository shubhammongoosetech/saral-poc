/**
 * SARAL Protocol V3 — Web3 Wallet Frontend Types
 */

export interface UserProfile {
  id: string;
  name?: string;
  email?: string;
  googleId?: string;
  mobile?: string;
  loginMethod: 'google' | 'mobile';
  createdAt: string;
}

export interface WorkingPolicy {
  userId?: string;
  timeRestrictionEnabled: boolean;
  startTime: string;
  endTime: string;
  days: string[];
  timezone: string;
  expiresAt?: string;
  locationRestrictionEnabled: boolean;
  allowedRegion?: string;
  geofenceEnabled?: boolean;
  lat?: number;
  lng?: number;
  radiusMeters?: number;
  updatedAt?: string;
}

export interface PolicyEvaluation {
  allowed: boolean;
  reason?: string;
  timeAllowed: boolean;
  locationAllowed: boolean;
  evaluatedAt: string;
  serverTime: string;
}

export interface ChainAddressDetail {
  blockchain: string;
  network: string;
  curve: string;
  address: string;
  status: 'ACTIVE_VERIFIED' | 'AWAITING_DKG_CURVE';
  verified: boolean;
  explorerUrl?: string;
  notes?: string;
}

export interface MultiChainAddresses {
  walletId: string;
  userId: string;
  status: 'READY';
  addresses: {
    mst: ChainAddressDetail;
    solana: ChainAddressDetail;
    bitcoin: ChainAddressDetail;
  };
  policyStatus?: {
    allowed: boolean;
    serverTime: string;
  };
}

export type GateStatus =
  | 'loading'
  | 'anonymous'
  | 'needs-mfa'
  | 'needs-policy'
  | 'creating-wallet'
  | 'ready'
  | 'access-restricted';
