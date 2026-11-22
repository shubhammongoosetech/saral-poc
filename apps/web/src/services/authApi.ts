import { httpClient } from './httpClient';
import { AuthResponse } from '../shared/api/types';

export interface RequestOtpResponse {
  success: boolean;
  devOtp?: string;
  message?: string;
}

export interface LoginOptions {
  googleClientId: string | null;
  developmentOtpEnabled: boolean;
}

export const authApi = {
  getLoginOptions: (signal?: AbortSignal): Promise<LoginOptions> =>
    httpClient.get('/auth/login-options', { signal }),

  loginWithGoogle: async (credential: string): Promise<AuthResponse> => {
    return httpClient.post<AuthResponse>('/auth/google', { credential });
  },

  requestOtp: async (mobile: string): Promise<RequestOtpResponse> => {
    return httpClient.post<RequestOtpResponse>('/auth/otp/request', { mobile });
  },

  verifyOtp: async (mobile: string, code: string): Promise<AuthResponse> => {
    return httpClient.post<AuthResponse>('/auth/otp/verify', {
      mobile,
      otp: code,
      code,
    });
  },

  logout: async (): Promise<void> => {
    try {
      await httpClient.post('/auth/logout', undefined, { keepalive: true });
    } catch {
      // Local sign-out remains available if the server cannot be reached.
    }
  },
};

export default authApi;

