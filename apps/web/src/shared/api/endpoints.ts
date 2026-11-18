import { apiClient } from "./client";
import {
  AuthResponse,
  MfaOtpResponse,
  MfaVerifyResponse,
  ProfileResponse,
  Policy,
  WalletResponse,
  AccessCheckResponse,
  SignResponse,
  TransactionsResponse,
} from "./types";

export const authApi = {
  loginWithGoogle: async (credential: string): Promise<AuthResponse> => {
    const res = await apiClient.post<AuthResponse>("/auth/google", {
      credential,
    });
    return res.data;
  },

  requestOtp: async (
    mobile: string,
  ): Promise<{ success: boolean; devOtp?: string }> => {
    const res = await apiClient.post<{ success: boolean; devOtp?: string }>(
      "/auth/otp/request",
      { mobile },
    );
    return res.data;
  },

  verifyOtp: async (mobile: string, code: string): Promise<AuthResponse> => {
    const res = await apiClient.post<AuthResponse>("/auth/otp/verify", {
      mobile,
      otp: code,
      code,
    });
    return res.data;
  },

  logout: async (): Promise<void> => {
    try {
      await apiClient.post('/auth/logout');
    } catch {
      // Backend uses stateless JWT session
    }
  },
};

export const mfaApi = {
  sendMfaOtp: async (): Promise<MfaOtpResponse> => {
    const res = await apiClient.post<MfaOtpResponse>("/mfa/send");
    return res.data;
  },

  verifyMfaOtp: async (otp: string): Promise<MfaVerifyResponse> => {
    const res = await apiClient.post<MfaVerifyResponse>("/mfa/verify", { otp });
    return res.data;
  },
};

export const profileApi = {
  getProfile: async (): Promise<ProfileResponse> => {
    const res = await apiClient.get<ProfileResponse>("/profile");
    return res.data;
  },

  savePolicy: async (policyData: {
    startTime: string;
    endTime: string;
    timezone: string;
    city: string;
    lat: number;
    lng: number;
    radiusKm: number;
  }): Promise<{ message: string; policy: Policy }> => {
    const res = await apiClient.post("/profile/policy", policyData);
    return res.data;
  },
};

export const walletApi = {
  getWallet: async (): Promise<WalletResponse> => {
    const res = await apiClient.get<WalletResponse>("/wallet");
    return res.data;
  },

  generateWallet: async (): Promise<WalletResponse> => {
    const res = await apiClient.post<WalletResponse>("/wallet/generate");
    return res.data;
  },

  checkAccess: async (lat?: number, lng?: number): Promise<AccessCheckResponse> => {
    const res = await apiClient.post<AccessCheckResponse>('/wallet/check-access', { lat, lng });
    return res.data;
  },

  signTransaction: async (data: {
    chain?: string;
    toAddress: string;
    amount: string;
    lat?: number;
    lng?: number;
  }): Promise<SignResponse> => {
    const res = await apiClient.post<SignResponse>("/wallet/sign", data);
    return res.data;
  },

  getTransactions: async (): Promise<TransactionsResponse> => {
    const res = await apiClient.get<TransactionsResponse>(
      "/wallet/transactions",
    );
    return res.data;
  },
};

export * from "./types";
