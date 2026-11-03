import { apiClient } from './client';

export interface User {
  id: string;
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

export interface EconomicStats {
  state: {
    totalValueSecuredMstc: number;
    stakedSst: number;
    stakedSmstc: number;
    totalEffectiveStake: number;
    currentSecurityRatio: number;
    currentEmissionRateApr: number;
    insuranceTreasuryBalanceMstc: number;
    totalUsageFeesProcessedMstc: number;
  };
  params: {
    targetSecurityRatio: number;
    minEmissionRateApr: number;
    maxEmissionRateApr: number;
    sstMaxSupplyCeiling: number;
  };
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

export const authApi = {
  loginWithGoogle: async (credential: string): Promise<AuthResponse> => {
    const res = await apiClient.post<AuthResponse>('/auth/google', { credential });
    return res.data;
  },

  requestOtp: async (mobile: string): Promise<{ success: boolean; message: string; devOtp?: string }> => {
    const res = await apiClient.post<{ success: boolean; message: string; devOtp?: string }>('/auth/otp/request', {
      mobile,
    });
    return res.data;
  },

  verifyOtp: async (mobile: string, otp: string): Promise<AuthResponse> => {
    const res = await apiClient.post<AuthResponse>('/auth/otp/verify', { mobile, otp });
    return res.data;
  },
};

export const mfaApi = {
  sendMfaOtp: async (): Promise<{ success: boolean; message: string; devOtp?: string }> => {
    const res = await apiClient.post<{ success: boolean; message: string; devOtp?: string }>('/mfa/send');
    return res.data;
  },

  verifyMfaOtp: async (otp: string): Promise<{ success: boolean; token: string; hasPolicy: boolean; hasWallet: boolean }> => {
    const res = await apiClient.post<{ success: boolean; token: string; hasPolicy: boolean; hasWallet: boolean }>(
      '/mfa/verify',
      { otp }
    );
    return res.data;
  },
};

export const profileApi = {
  getProfile: async (): Promise<{
    user: User;
    mfa: { type: string; verified_at: string | null } | null;
    policy: WorkPolicy | null;
    wallet: { address: string; public_key: string } | null;
    mfaVerified: boolean;
    hasPolicy: boolean;
    hasWallet: boolean;
  }> => {
    const res = await apiClient.get('/profile');
    return res.data;
  },

  savePolicy: async (data: {
    startTime: string;
    endTime: string;
    timezone: string;
    city: string;
    lat: number;
    lng: number;
    radiusKm?: number;
  }): Promise<{ success: boolean; policy: WorkPolicy; message: string }> => {
    const res = await apiClient.post('/profile/policy', data);
    return res.data;
  },
};

export const walletApi = {
  getWallet: async (): Promise<{ hasWallet: boolean; wallet: WalletData | null }> => {
    const res = await apiClient.get('/wallet');
    return res.data;
  },

  generateWallet: async (
    n?: number,
    threshold?: number
  ): Promise<{ success: boolean; wallet: WalletData; message: string }> => {
    const res = await apiClient.post('/wallet/generate', { n, threshold });
    return res.data;
  },

  checkAccess: async (lat?: number, lng?: number): Promise<PolicyCheckResponse> => {
    const res = await apiClient.post<PolicyCheckResponse>('/wallet/check-access', {
      lat,
      lng,
    });
    return res.data;
  },

  signTransaction: async (data: {
    toAddress: string;
    amount: string;
    lat?: number;
    lng?: number;
  }): Promise<{ success: boolean; txHash: string; broadcasted: boolean; message: string; explorerUrl?: string }> => {
    const res = await apiClient.post('/wallet/sign', data);
    return res.data;
  },

  getTransactions: async (): Promise<{
    transactions: Array<{
      tx_hash: string;
      to_address: string;
      amount: string;
      created_at: string;
    }>;
  }> => {
    const res = await apiClient.get('/wallet/transactions');
    return res.data;
  },

  getClusterHealth: async (): Promise<ClusterStatus> => {
    const res = await apiClient.get<ClusterStatus>('/wallet/cluster-health');
    return res.data;
  },

  getEconomicStats: async (): Promise<EconomicStats> => {
    const res = await apiClient.get<EconomicStats>('/wallet/economic-stats');
    return res.data;
  },

  initiateRecovery: async (reason: string, timelockHours?: number): Promise<{ success: boolean; message: string; request: any }> => {
    const res = await apiClient.post('/wallet/recovery/initiate', { reason, timelockHours });
    return res.data;
  },

  cancelRecovery: async (requestId: string, reason?: string): Promise<{ success: boolean; message: string }> => {
    const res = await apiClient.post('/wallet/recovery/cancel', { requestId, reason });
    return res.data;
  },

  getRecoveryLogs: async (): Promise<{ logs: any[] }> => {
    const res = await apiClient.get('/wallet/recovery/logs');
    return res.data;
  },
};
