/**
 * SARAL Protocol V3 — Typed Authentication & Wallet API Client
 */

import {
  UserProfile,
  WorkingPolicy,
  PolicyEvaluation,
  MultiChainAddresses,
} from '../types/auth';

const AUTH_URL = import.meta.env.VITE_AUTH_SERVER_URL || 'http://localhost:3001';

class AuthApiClient {
  private token: string | null = null;

  constructor() {
    this.token = localStorage.getItem('saral_session_token');
  }

  public setToken(token: string | null): void {
    this.token = token;
    if (token) {
      localStorage.setItem('saral_session_token', token);
    } else {
      localStorage.removeItem('saral_session_token');
    }
  }

  public getToken(): string | null {
    return this.token;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const url = `${AUTH_URL.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {}),
    };

    if (this.token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    try {
      const res = await fetch(url, { ...options, headers });
      const json = await res.json();
      if (!res.ok || json.success === false) {
        const error: any = new Error(json.error || `HTTP ${res.status}: ${res.statusText}`);
        error.statusCode = res.status;
        error.data = json;
        throw error;
      }
      return json as T;
    } catch (err: any) {
      if (err.statusCode) throw err;
      throw new Error(err.message || 'Network error connecting to SARAL services');
    }
  }

  public async loginWithGoogle(credential: string): Promise<{
    user: UserProfile;
    token: string;
    mfaEnrolled: boolean;
    mfaVerified: boolean;
    hasPolicy: boolean;
    hasWallet: boolean;
  }> {
    const res = await this.request<any>('auth/google', {
      method: 'POST',
      body: JSON.stringify({ credential }),
    });
    if (res.token) this.setToken(res.token);
    return res;
  }

  public async requestPhoneOtp(mobile: string): Promise<{
    success: boolean;
    mobile: string;
    cooldownSeconds: number;
    devOtp?: string;
  }> {
    return this.request<any>('auth/phone/request-otp', {
      method: 'POST',
      body: JSON.stringify({ mobile }),
    });
  }

  public async verifyPhoneOtp(mobile: string, otp: string): Promise<{
    user: UserProfile;
    token: string;
    mfaEnrolled: boolean;
    mfaVerified: boolean;
    hasPolicy: boolean;
    hasWallet: boolean;
  }> {
    const res = await this.request<any>('auth/phone/verify-otp', {
      method: 'POST',
      body: JSON.stringify({ mobile, otp }),
    });
    if (res.token) this.setToken(res.token);
    return res;
  }

  public async linkAccount(targetMethod: 'google' | 'mobile', identifier: string): Promise<{ success: boolean; user: UserProfile }> {
    return this.request<any>('auth/link-account', {
      method: 'POST',
      body: JSON.stringify({ targetMethod, identifier }),
    });
  }

  public async enrollMfa(): Promise<{
    secret: string;
    qrUri: string;
    recoveryCodes: string[];
  }> {
    return this.request<any>('auth/mfa/enroll', { method: 'POST' });
  }

  public async verifyMfa(code: string): Promise<{
    success: boolean;
    token: string;
    method?: string;
    hasPolicy: boolean;
    hasWallet: boolean;
  }> {
    const res = await this.request<any>('auth/mfa/verify', {
      method: 'POST',
      body: JSON.stringify({ code }),
    });
    if (res.token) this.setToken(res.token);
    return res;
  }

  public async getSession(): Promise<{
    user: UserProfile;
    mfaEnrolled: boolean;
    mfaVerified: boolean;
    hasPolicy: boolean;
    hasWallet: boolean;
    policy: WorkingPolicy | null;
  }> {
    return this.request<any>('auth/session', { method: 'GET' });
  }

  public async getWorkingPolicy(): Promise<{ policy: WorkingPolicy | null }> {
    return this.request<any>('wallet/policy', { method: 'GET' });
  }

  public async saveWorkingPolicy(policy: Partial<WorkingPolicy>): Promise<{ policy: WorkingPolicy }> {
    return this.request<any>('wallet/policy', {
      method: 'PUT',
      body: JSON.stringify(policy),
    });
  }

  public async evaluateWorkingPolicy(lat?: number, lng?: number): Promise<PolicyEvaluation> {
    return this.request<PolicyEvaluation>('wallet/policy/evaluate', {
      method: 'POST',
      body: JSON.stringify({ lat, lng }),
    });
  }

  public async getWalletStatus(): Promise<{
    hasWallet: boolean;
    walletId: string | null;
    status: string;
    hasPolicy: boolean;
    mfaVerified: boolean;
  }> {
    return this.request<any>('wallet/status', { method: 'GET' });
  }

  public async createWallet(lat?: number, lng?: number): Promise<{
    success: boolean;
    isNew: boolean;
    walletId: string;
    status: string;
    addresses: MultiChainAddresses['addresses'];
  }> {
    return this.request<any>('wallet/create', {
      method: 'POST',
      body: JSON.stringify({ lat, lng }),
    });
  }

  public async getMultiChainAddresses(lat?: number, lng?: number): Promise<MultiChainAddresses> {
    const query = lat !== undefined && lng !== undefined ? `?lat=${lat}&lng=${lng}` : '';
    return this.request<MultiChainAddresses>(`wallet/addresses${query}`, { method: 'GET' });
  }

  public logout(): void {
    this.setToken(null);
  }
}

export const authApi = new AuthApiClient();
